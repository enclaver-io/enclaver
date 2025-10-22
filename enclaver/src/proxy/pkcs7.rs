#![allow(dead_code, unused)]

use anyhow::{Result, anyhow, bail};
use asn1_rs::{
    Any, Class, FromBer, Integer, OctetString, Oid, OptTaggedParser, SetOf, Tag, Tagged,
};
use asn1_rs::{BerSequence, oid};
use cbc::cipher::crypto_common::KeyIvInit;
use cbc::cipher::{BlockDecryptMut, block_padding};
use rsa::traits::PaddingScheme;
use rsa::{RsaPrivateKey, oaep::Oaep};
use sha2::Sha256;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const OID_NIST_SHA_256: Oid<'static> = oid!(2.16.840.1.101.3.4.2.1);
const OID_NIST_AES256_CBC: Oid<'static> = oid!(2.16.840.1.101.3.4.1.42);
const OID_PKCS1_RSA_OAEP: Oid<'static> = oid!(1.2.840.113549.1.1.7);
const OID_PKCS1_MGF: Oid<'static> = oid!(1.2.840.113549.1.1.8);
const OID_PKCS7_ENVELOPED_DATA: Oid<'static> = oid!(1.2.840.113549.1.7.3);
const OID_PKCS7_DATA: Oid<'static> = oid!(1.2.840.113549.1.7.1);

/*
ContentInfo ::= SEQUENCE {
  contentType ContentType,
  content [0] EXPLICIT ANY DEFINED BY contentType }
*/

#[derive(BerSequence, Debug)]
pub(crate) struct ContentInfo<'a> {
    pub content_type: Oid<'a>,

    #[tag_explicit(0)]
    pub content: EnvelopedData<'a>,
}

impl<'a> ContentInfo<'a> {
    pub fn parse_ber(ber: &'a [u8]) -> Result<Self> {
        let (rem, ci) = Self::from_ber(ber)?;

        if !rem.is_empty() {
            bail!("trailing {} bytes after parsing ContentInfo", rem.len());
        }

        ci.validate()?;

        Ok(ci)
    }

    fn validate(&self) -> Result<()> {
        if self.content_type != OID_PKCS7_ENVELOPED_DATA {
            bail!(
                "unexpected content type: {}, expected {}",
                self.content_type,
                OID_PKCS7_ENVELOPED_DATA
            );
        }

        self.content.validate()
    }

    pub fn decrypt_content(&self, priv_key: &RsaPrivateKey) -> Result<Vec<u8>> {
        let datakey = self.decrypt_key(priv_key)?;
        self.content
            .encrypted_content_info
            .decrypt_content(&datakey)
    }

    fn decrypt_key(&self, priv_key: &RsaPrivateKey) -> Result<Vec<u8>> {
        let ciphertext = self
            .content
            .recipient_infos
            .iter()
            .next()
            .unwrap()
            .encrypted_key
            .as_ref();

        let padding = Oaep::new::<Sha256>();

        Ok(priv_key.decrypt(padding, ciphertext)?)
    }
}

/*
EnvelopedData ::= SEQUENCE {
  version CMSVersion,
  originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
  recipientInfos RecipientInfos,
  encryptedContentInfo EncryptedContentInfo,
  unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }

RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
*/

#[derive(BerSequence, Debug)]
pub(crate) struct EnvelopedData<'a> {
    pub version: Integer<'a>,

    #[optional]
    #[tag_implicit(0)]
    pub originator_info: Option<OriginatorInfo<'a>>,

    pub recipient_infos: SetOf<KeyTransRecipientInfo<'a>>,

    pub encrypted_content_info: EncryptedContentInfo<'a>,

    #[optional]
    #[tag_implicit(1)]
    pub unprotected_attrs: Option<SetOf<Attribute<'a>>>,
}

impl EnvelopedData<'_> {
    fn validate(&self) -> Result<()> {
        let ver = self.version.as_i32()?;
        if ver != 2 {
            bail!("unexpected EnvelopedData.version: {ver}, expected 2");
        }

        if self.recipient_infos.len() != 1 {
            bail!(
                "unexpected EnvelopedData.recipient_infos length: {}, expected 1",
                self.recipient_infos.len()
            );
        }

        self.recipient_infos.iter().next().unwrap().validate()?;

        self.encrypted_content_info.validate()
    }
}

/*
OriginatorInfo ::= SEQUENCE {
  certs [0] IMPLICIT CertificateSet OPTIONAL,
  crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }
*/

#[derive(BerSequence, Debug)]
pub(crate) struct OriginatorInfo<'a> {
    #[optional]
    #[tag_implicit(0)]
    pub certs: Option<SetOf<Any<'a>>>,

    #[optional]
    #[tag_implicit(1)]
    pub crls: Option<SetOf<Any<'a>>>,
}

/*
RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo

RecipientInfo ::= CHOICE {
  ktri KeyTransRecipientInfo,
  kari [1] KeyAgreeRecipientInfo,
  kekri [2] KEKRecipientInfo,
  pwri [3] PasswordRecipientinfo,
  ori [4] OtherRecipientInfo }

KeyTransRecipientInfo ::= SEQUENCE {
  version CMSVersion,  -- always set to 0 or 2
  rid RecipientIdentifier,
  keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
  encryptedKey EncryptedKey }
*/

#[derive(BerSequence, Debug)]
pub(crate) struct KeyTransRecipientInfo<'a> {
    pub version: Integer<'a>,
    pub rid: Any<'a>,
    pub key_encryption_algorithm: AlgorithmIdentifier<'a>,
    pub encrypted_key: OctetString<'a>,
}

impl<'a> KeyTransRecipientInfo<'a> {
    fn validate(&self) -> Result<()> {
        let ver = self.version.as_i32()?;
        if ver != 2 {
            bail!("unexpected KeyTransRecipientInfo.version: {ver}, expected 2");
        }

        let key_algo = &self.key_encryption_algorithm;

        if key_algo.algorithm != OID_PKCS1_RSA_OAEP {
            bail!(
                "unexpected KeyTransRecipientInfo.key_encryption_algorithm.algorithm: {}, expected {OID_PKCS1_RSA_OAEP}",
                key_algo.algorithm
            );
        }

        if let Some(ref params) = key_algo.parameters {
            let rsa_oaep_params: RsaesOaepParameters<'a> = params.clone().try_into()?;
            rsa_oaep_params.validate()?;
        } else {
            bail!("Missing KeyTransRecipientInfo.key_encryption_algorithm.parameters");
        }

        Ok(())
    }
}

/*
RecipientIdentifier ::= CHOICE {
  issuerAndSerialNumber IssuerAndSerialNumber,
  subjectKeyIdentifier [0] SubjectKeyIdentifier }

AlgorithmIdentifier{ALGORITHM-TYPE, ALGORITHM-TYPE:AlgorithmSet} ::=
  SEQUENCE {
    algorithm   ALGORITHM-TYPE.&id({AlgorithmSet}),
      parameters  ALGORITHM-TYPE.
             &Params({AlgorithmSet}{@algorithm}) OPTIONAL
  }

EncryptedKey ::= OCTET STRING
*/

#[derive(BerSequence, Debug)]
pub(crate) struct AlgorithmIdentifier<'a> {
    pub algorithm: Oid<'a>,

    #[optional]
    pub parameters: Option<Any<'a>>,
}

/*
RSAES-OAEP-params  ::=  SEQUENCE  {
  hashFunc    [0] AlgorithmIdentifier DEFAULT sha1Identifier,
  maskGenFunc [1] AlgorithmIdentifier DEFAULT mgf1SHA1Identifier,
  pSourceFunc [2] AlgorithmIdentifier DEFAULT
                    pSpecifiedEmptyIdentifier  }
*/

#[derive(Debug)]
pub(crate) struct RsaesOaepParameters<'a> {
    hash_alg: Option<AlgorithmIdentifier<'a>>,
    mask_gen_alg: Option<AlgorithmIdentifier<'a>>,
    _p_source_alg: Option<AlgorithmIdentifier<'a>>,
}

impl RsaesOaepParameters<'_> {
    fn validate(&self) -> Result<()> {
        if let Some(ref alg) = self.hash_alg {
            if alg.algorithm != OID_NIST_SHA_256 {
                bail!(
                    "unexpected KeyTransRecipientInfo.key_encryption_algorithm.hash_func: {}, expected {OID_NIST_SHA_256}",
                    alg.algorithm
                );
            }
        } else {
            bail!(
                "missing KeyTransRecipientInfo.key_encryption_algorithm.hash_func, expected {OID_NIST_SHA_256}"
            );
        }

        if let Some(ref alg) = self.mask_gen_alg {
            if alg.algorithm != OID_PKCS1_MGF {
                bail!(
                    "unexpected KeyTransRecipientInfo.key_encryption_algorithm.mask_gen_func: {}, expected {OID_PKCS1_MGF}",
                    alg.algorithm
                );
            }

            if let Some(ref params) = alg.parameters {
                let (_, mgf_hash) = Oid::from_ber(params.as_bytes())?;
                if mgf_hash != OID_NIST_SHA_256 {
                    bail!(
                        "unexpected KeyTransRecipientInfo.key_encryption_algorithm.mask_gen_func.hash: {}, expected {OID_NIST_SHA_256}",
                        mgf_hash
                    );
                }
            } else {
                bail!(
                    "missing KeyTransRecipientInfo.key_encryption_algorithm.mask_gen_func.parameters"
                );
            }
        } else {
            bail!(
                "missing KeyTransRecipientInfo.key_encryption_algorithm.parameters.mask_gen_func, expected {OID_PKCS1_MGF}"
            );
        }

        Ok(())
    }
}

impl<'a> TryFrom<Any<'a>> for RsaesOaepParameters<'a> {
    type Error = asn1_rs::Error;

    fn try_from(value: Any<'a>) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

//     hashFunc          [0] AlgorithmIdentifier DEFAULT
//                              sha1Identifier,
//     maskGenFunc       [1] AlgorithmIdentifier DEFAULT
//                              mgf1SHA1Identifier,
//     pSourceFunc       [2] AlgorithmIdentifier DEFAULT
//                              pSpecifiedEmptyIdentifier  }
impl<'a, 'b> TryFrom<&'b Any<'a>> for RsaesOaepParameters<'a> {
    type Error = asn1_rs::Error;

    fn try_from(value: &'b Any<'a>) -> Result<Self, Self::Error> {
        value.tag().assert_eq(Tag::Sequence)?;
        let i = &value.data;

        let (i, hash_alg) = OptTaggedParser::new(Class::ContextSpecific, Tag(0))
            .parse_ber(i, |_, inner| AlgorithmIdentifier::from_ber(inner))?;

        let (i, mask_gen_alg) = OptTaggedParser::new(Class::ContextSpecific, Tag(1))
            .parse_ber(i, |_, inner| AlgorithmIdentifier::from_ber(inner))?;

        let (_, p_source_alg) = OptTaggedParser::new(Class::ContextSpecific, Tag(2))
            .parse_ber(i, |_, inner| AlgorithmIdentifier::from_ber(inner))?;

        Ok(Self {
            hash_alg,
            mask_gen_alg,
            _p_source_alg: p_source_alg,
        })
    }
}

pub type Aes256CBCParameter<'a> = OctetString<'a>;

/*
EncryptedContentInfo ::= SEQUENCE {
  contentType ContentType,
  contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
  encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
*/

#[derive(BerSequence, Debug)]
pub(crate) struct EncryptedContentInfo<'a> {
    pub content_type: Oid<'a>,
    pub content_encryption_algorithm: AlgorithmIdentifier<'a>,
    pub encrypted_content: Any<'a>,
}

impl EncryptedContentInfo<'_> {
    fn validate(&self) -> Result<()> {
        if self.content_type != OID_PKCS7_DATA {
            bail!(
                "unexpected EncryptedContentInfo.content_type: {}, expected {OID_PKCS7_DATA}",
                self.content_type
            );
        }

        if self.content_encryption_algorithm.algorithm != OID_NIST_AES256_CBC {
            bail!(
                "unexpected EncryptedContentInfo.content_encryption_algorithm: {}, expected {OID_NIST_AES256_CBC}",
                self.content_encryption_algorithm.algorithm
            );
        }

        // Ignoring the OPTIONAL directive, it should always be there in our use case
        let any = &self.encrypted_content;

        if any.header.class() != Class::ContextSpecific {
            bail!(
                "unexpected EncryptedContentInfo.encrypted_content.class: {}, expected {}",
                any.header.class(),
                Class::ContextSpecific
            );
        }

        if any.header.tag().0 != 0 {
            bail!(
                "unexpected EncryptedContentInfo.encrypted_content.tag: {}, expected 0",
                any.header.tag().0
            );
        }

        Ok(())
    }

    fn decrypt_content(&self, datakey: &[u8]) -> Result<Vec<u8>> {
        let iv: Aes256CBCParameter = self
            .content_encryption_algorithm
            .parameters
            .as_ref()
            .unwrap()
            .try_into()
            .unwrap();

        let ciphertext = self.combined_content()?;
        let dec = Aes256CbcDec::new(datakey.into(), iv.as_ref().into());
        Ok(dec
            .decrypt_padded_vec_mut::<block_padding::Pkcs7>(&ciphertext)
            .unwrap())
    }

    fn combined_content(&self) -> Result<Vec<u8>> {
        // Ignoring the OPTIONAL directive, it should always be there in our use case
        let any = &self.encrypted_content;

        if any.header.is_constructed() {
            let mut data = any.data;
            let mut combined = Vec::new();

            while !data.is_empty() {
                // concatentate the inner parts
                let (rem, part) = OctetString::from_ber(data)?;
                combined.extend_from_slice(part.as_ref());
                data = rem;
            }

            Ok(combined)
        } else {
            let octets: OctetString = any.try_into()?;
            Ok(octets.as_ref().to_vec())
        }
    }
}
/*
Attribute ::= SEQUENCE {
  attrType OBJECT IDENTIFIER,
  attrValues SET OF AttributeValue }
*/

#[derive(BerSequence, Debug)]
pub(crate) struct Attribute<'a> {
    pub attr_type: Oid<'a>,
    pub attr_values: SetOf<Any<'a>>,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::ContentInfo;
    use assert2::assert;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::RsaPrivateKey;

    pub(crate) const INPUT: &str = "\
MIAGCSqGSIb3DQEHA6CAMIACAQIxggFrMIIBZwIBAoAg+wnprylA3c8NK79jWMmDr0b8X9ztv\
KJR1UzqtNBpzYkwPAYJKoZIhvcNAQEHMC+gDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQ\
EBCDANBglghkgBZQMEAgEFAASCAQBtKYAuknZaRt5SOgmPmzvmelJ/gFx6tetIhN9u5FSOVzG\
BkF5jSqVDABxBybusmdi1y4OQ+HAr1A6nKyVSzjq2nCPqF1qEIduJlxXDDQkP+E7f1+9AVCr/\
mUDvc+5ZzFWGcfH9hHGDhLM3qrKMIVEx97593kXwOXDBNY9jQ52Yx4pCK4PHxLRK0mPuA9y48\
wr3AWj711tV4tHU3MJvnp3y3vB306OnH2mLfcuML5nOjgCEIQaaovkJkTMYmmN1GdwvG/Pilh\
c7JLJAVKSPiCRa2UuVa8S9cU50nxYidMi6cKSY6WzHN2unalWgIRb3J43VDH0A5jQgSejCFCY\
1YkPpMIAGCSqGSIb3DQEHATAdBglghkgBZQMEASoEECwv8RFq5vhXP9WP1E+YBiSggAQQJjqX\
tzpe8K1dsCdK+fwpDAAAAAAAAAAAAAA=";

    pub(crate) const PRIVATE_KEY: &str = "\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+4nqOJ4xmYtE0\
rdCY4YwvA/bH15xdpYoC2SoMlrytOhUK77awbfJKwlwiXxaKoaJOOaV+neci8BRi\
s0/8mKr7VoX7GG5E4lVj/8nl8LBeq5DAZUlasyJpQ1+1k3zU2vWYJDQxU/6tDp63\
opYZx3QZqEHjHYIA+N0xOexTfMAbWRntZU8M2ZNpxxkdYLbQRRprpMvt6aH8PvkF\
Y1iFKJJJQ7Onkl8P664KJvZcPyJRrbk2ORXYZVcuowT2nPTXaEAutlCx6mTyzsrz\
/Pq8k4RQtQlBfw0+ocMwmfHxeXIstAr/bY8vXgOi/071cFF9kVMQFjud6gs4sJ0Q\
mXdqrphHAgMBAAECggEAODR1g5/vfkJAeXNohWt8HGfdZTB+UTCp93a8I+LKgXMl\
uQemUkK9Yffiqxg2ifFX2hKtQR/7a9UnG3zS43yMc98hKjMiXNQL8prhdvws4mNA\
BvaL59HxIu98oflge0hRok+espuZ1JkGcOnFqqeI7vkVFWud2O1uK81zYY3M/v/1\
uXXiYBkM2q40FJKuL1IhtV6SUsjn0qmam+Wt3dQOpXkJ7bjBJaXYR4IMiDmL0woW\
ZabQaOuOc1ck77bPmY1ft2y654zF0aKHMo1h4+hGBsch1/GlBqxWDyA5+HUUwePq\
CNK0C8DBgnsCfxGZ/k5/tasbt57jWkjIYYnmYdUoAQKBgQDwRNLGYRDrP5PiIQol\
uuNv72ndGn/npSW5dBuyezs5Clh0ewYqZHkeBucyqgciQhsl5YofmNe4VkW2ycht\
ijzLho7IUgF0fB5adfUJUr4qQ+dDN1NbzlTybXKn9AFUTbaQ/2yXyT7yAcY61y9J\
bGXc59RSpVYeO1k0ep+aqVFcAQKBgQDLYevU4t+HVZSDWXvtiVMqXakxe/wnQyq+\
M3hQA2awc5O8ov5WafOr1zojlNiZ/s4b3meWnW0SxH813B8N8x5OIlgwbbYO4LxJ\
2LLVcbYfrXTrvdfWUJa5xAMSGnSVwlN03pN+mmSseJTUJaD4/20aYPJi/CALfJBF\
uyGYke4URwKBgFiRJhkWYsQ09XBfuXva/keeuylTwV5EVDmegS8zmcsW8zBMwSMT\
UkotRUA5yNNqBtPbXyTylGJQ+vW8P/ORB4QGn89b20lzD0VNQfwj0hGGYlM2q7Wl\
w05x5dffbDYFR4z/eqog9uECom3CMJ4iJRJfKrckVzBhtCpSIU9DpsgBAoGBAKAz\
I3Xutq99Q5wq0ikKsE2AtRLbXIT4rSRgmnY8F5kJkOdXZAthLaS/xXXderfiMytU\
hjfnDNFpoeIk3vk39TkKaHjNEkip0OZCIKtsBE7zbFN8mBSiKfdtZBXQbODBzscR\
wxBIQOBxoplwgllfqOrMTmCVxBAIMAQdIJty5xtlAoGBAM9+8qkG1g9nZO4fYxXo\
4VnlV25W7Ki+PNFAqCO/73JfBqvlVDn8o9xXZmEWbb3L+WVm5KDFjBmHblf9v2jI\
IzBcCfCv6hZssdGPGDXMDPB45pw2HYJHGxyBK5T8jr+ja9zcu2IyD11u3a/LBn9G\
UBYkWlVgulDg28KBqahr9r04";

    #[test]
    fn test_content_info() {
        let ber = base64::decode(INPUT).unwrap();

        let ci = ContentInfo::parse_ber(&ber).unwrap();
        ci.validate().unwrap();

        let key_der = base64::decode(PRIVATE_KEY).unwrap();
        let priv_key = RsaPrivateKey::from_pkcs8_der(&key_der).unwrap();

        let plaintext = ci.decrypt_content(&priv_key).unwrap();
        let msg = std::str::from_utf8(&plaintext).unwrap();

        assert!(msg == "Hello, World");
    }
}
