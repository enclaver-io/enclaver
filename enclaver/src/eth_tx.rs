use anyhow::{Result, anyhow};
use rlp::{Rlp, RlpStream};
use sha3::{Digest, Keccak256};

pub const EIP1559_TX_TYPE: u8 = 0x02;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessListEntry {
    pub address: [u8; 20],
    pub storage_keys: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedEip1559Tx {
    pub chain_id: Vec<u8>,
    pub nonce: Vec<u8>,
    pub max_priority_fee_per_gas: Vec<u8>,
    pub max_fee_per_gas: Vec<u8>,
    pub gas_limit: Vec<u8>,
    pub to: Option<[u8; 20]>,
    pub value: Vec<u8>,
    pub data: Vec<u8>,
    pub access_list: Vec<AccessListEntry>,
}

#[derive(Debug, Clone)]
pub struct TxSignature {
    pub y_parity: u8,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

impl TxSignature {
    pub fn from_recoverable_bytes(sig: &[u8; 65]) -> Result<Self> {
        let y_parity = sig[64];
        if y_parity > 1 {
            return Err(anyhow!("invalid y-parity {}, expected 0 or 1", y_parity));
        }
        let r = trim_scalar(&sig[0..32]);
        let s = trim_scalar(&sig[32..64]);
        Ok(Self { y_parity, r, s })
    }
}

impl UnsignedEip1559Tx {
    pub fn from_raw_payload(raw: &[u8]) -> Result<Self> {
        if raw.is_empty() {
            return Err(anyhow!("raw payload is empty"));
        }
        if raw[0] != EIP1559_TX_TYPE {
            return Err(anyhow!("raw payload must start with 0x02"));
        }
        let rlp = Rlp::new(&raw[1..]);
        if !rlp.is_list() {
            return Err(anyhow!("typed transaction body is not an RLP list"));
        }
        let fields = rlp.item_count()?;
        if fields != 9 {
            return Err(anyhow!(
                "expected 9 fields in EIP-1559 payload, found {}",
                fields
            ));
        }

        let to_bytes: Vec<u8> = rlp.val_at(5)?;
        let to = if to_bytes.is_empty() {
            None
        } else {
            Some(to_fixed_array::<20>(&to_bytes)?)
        };

        let access_list = parse_access_list(&rlp.at(8)?)?;

        Ok(Self {
            chain_id: rlp.val_at(0)?,
            nonce: rlp.val_at(1)?,
            max_priority_fee_per_gas: rlp.val_at(2)?,
            max_fee_per_gas: rlp.val_at(3)?,
            gas_limit: rlp.val_at(4)?,
            to,
            value: rlp.val_at(6)?,
            data: rlp.val_at(7)?,
            access_list,
        })
    }

    pub fn signing_payload(&self) -> Vec<u8> {
        let mut stream = RlpStream::new();
        stream.begin_list(9);
        self.append_base_fields(&mut stream);
        prepend_type_prefix(stream.out().to_vec())
    }

    pub fn finalize(&self, signature: &TxSignature) -> Vec<u8> {
        let mut stream = RlpStream::new();
        stream.begin_list(12);
        self.append_base_fields(&mut stream);
        stream.append(&signature.y_parity);
        stream.append(&signature.r);
        stream.append(&signature.s);
        prepend_type_prefix(stream.out().to_vec())
    }

    fn append_base_fields(&self, stream: &mut RlpStream) {
        stream.append(&self.chain_id);
        stream.append(&self.nonce);
        stream.append(&self.max_priority_fee_per_gas);
        stream.append(&self.max_fee_per_gas);
        stream.append(&self.gas_limit);
        match &self.to {
            Some(addr) => stream.append(&addr.to_vec()),
            None => stream.append_empty_data(),
        };
        stream.append(&self.value);
        stream.append(&self.data);
        stream.begin_list(self.access_list.len());
        for entry in &self.access_list {
            stream.begin_list(2);
            stream.append(&entry.address.to_vec());
            stream.begin_list(entry.storage_keys.len());
            for key in &entry.storage_keys {
                stream.append(&key.to_vec());
            }
        }
    }
}

pub fn parse_scalar_hex(input: &str) -> Result<Vec<u8>> {
    let bytes = parse_hex_bytes(input)?;
    Ok(trim_scalar(&bytes))
}

pub fn parse_data_hex(input: &str) -> Result<Vec<u8>> {
    parse_hex_bytes(input)
}

pub fn parse_address_hex(input: &str) -> Result<[u8; 20]> {
    let bytes = parse_hex_bytes(input)?;
    if bytes.len() != 20 {
        return Err(anyhow!("address must be 20 bytes, found {}", bytes.len()));
    }
    to_fixed_array::<20>(&bytes)
}

pub fn parse_storage_key_hex(input: &str) -> Result<[u8; 32]> {
    let bytes = parse_hex_bytes(input)?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "storage key must be 32 bytes, found {}",
            bytes.len()
        ));
    }
    to_fixed_array::<32>(&bytes)
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

fn parse_hex_bytes(input: &str) -> Result<Vec<u8>> {
    let trimmed = input.trim();
    let without_prefix = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if without_prefix.is_empty() {
        return Ok(Vec::new());
    }
    if !without_prefix.len().is_multiple_of(2) {
        let mut padded = String::with_capacity(without_prefix.len() + 1);
        padded.push('0');
        padded.push_str(without_prefix);
        Ok(hex::decode(padded)?)
    } else {
        Ok(hex::decode(without_prefix)?)
    }
}

fn trim_scalar(bytes: &[u8]) -> Vec<u8> {
    if bytes.iter().all(|&b| b == 0) {
        return Vec::new();
    }
    match bytes.iter().position(|&b| b != 0) {
        Some(idx) => bytes[idx..].to_vec(),
        None => Vec::new(),
    }
}

fn parse_access_list(rlp: &Rlp) -> Result<Vec<AccessListEntry>> {
    if !rlp.is_list() {
        return Err(anyhow!("access list must be an RLP list"));
    }
    let mut result = Vec::with_capacity(rlp.item_count()?);
    for idx in 0..rlp.item_count()? {
        let entry_rlp = rlp.at(idx)?;
        if !entry_rlp.is_list() || entry_rlp.item_count()? != 2 {
            return Err(anyhow!("access list entry must contain address and keys"));
        }
        let address_bytes: Vec<u8> = entry_rlp.val_at(0)?;
        let address = to_fixed_array::<20>(&address_bytes)?;
        let keys_rlp = entry_rlp.at(1)?;
        if !keys_rlp.is_list() {
            return Err(anyhow!("storage keys must be encoded as a list"));
        }
        let mut storage_keys = Vec::with_capacity(keys_rlp.item_count()?);
        for key_idx in 0..keys_rlp.item_count()? {
            let key_bytes: Vec<u8> = keys_rlp.val_at(key_idx)?;
            storage_keys.push(to_fixed_array::<32>(&key_bytes)?);
        }
        result.push(AccessListEntry {
            address,
            storage_keys,
        });
    }
    Ok(result)
}

fn to_fixed_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    if bytes.len() != N {
        return Err(anyhow!("expected {} bytes, found {}", N, bytes.len()));
    }
    let mut array = [0u8; N];
    array.copy_from_slice(bytes);
    Ok(array)
}

fn prepend_type_prefix(mut payload: Vec<u8>) -> Vec<u8> {
    let mut result = Vec::with_capacity(1 + payload.len());
    result.push(EIP1559_TX_TYPE);
    result.append(&mut payload);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tx() -> UnsignedEip1559Tx {
        UnsignedEip1559Tx {
            chain_id: parse_scalar_hex("0x1").unwrap(),
            nonce: parse_scalar_hex("0x2a").unwrap(),
            max_priority_fee_per_gas: parse_scalar_hex("0x3b9aca00").unwrap(),
            max_fee_per_gas: parse_scalar_hex("0x77359400").unwrap(),
            gas_limit: parse_scalar_hex("0x5208").unwrap(),
            to: Some(parse_address_hex("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap()),
            value: parse_scalar_hex("0x0").unwrap(),
            data: parse_data_hex("0xdeadbeef").unwrap(),
            access_list: vec![AccessListEntry {
                address: parse_address_hex("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
                storage_keys: vec![
                    parse_storage_key_hex(
                        "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    )
                    .unwrap(),
                ],
            }],
        }
    }

    #[test]
    fn signing_payload_roundtrip() {
        let tx = sample_tx();
        let payload = tx.signing_payload();
        assert_eq!(payload[0], EIP1559_TX_TYPE);
        let parsed = UnsignedEip1559Tx::from_raw_payload(&payload).unwrap();
        assert_eq!(parsed, tx);
    }

    #[test]
    fn finalize_includes_signature() {
        let tx = sample_tx();
        let mut signature_bytes = [0u8; 65];
        signature_bytes[..32].copy_from_slice(&[0x11; 32]);
        signature_bytes[32..64].copy_from_slice(&[0x22; 32]);
        signature_bytes[64] = 1;

        let signature = TxSignature::from_recoverable_bytes(&signature_bytes).unwrap();
        let raw_tx = tx.finalize(&signature);

        assert_eq!(raw_tx[0], EIP1559_TX_TYPE);
        assert!(raw_tx.len() > tx.signing_payload().len());
    }
}
