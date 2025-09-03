import os
import base64
import boto3

KMS_SYMMETRIC_KEY_ID = os.environ['KMS_SYMMETRIC_KEY_ID']
KMS_ASYMMETRIC_KEY_ID = os.environ['KMS_ASYMMETRIC_KEY_ID']

PLAINTEXT = 'All Quiet on the Western Front'

def test_decrypt(kms_client):
  ciphertext = kms_client.encrypt(KeyId=KMS_SYMMETRIC_KEY_ID, Plaintext=PLAINTEXT)['CiphertextBlob']
  plaintext = kms_client.decrypt(CiphertextBlob=ciphertext, KeyId=KMS_SYMMETRIC_KEY_ID)['Plaintext'].decode('utf-8')

  assert PLAINTEXT == plaintext
  print("Decryption test passed")

def test_generate_data_key(kms_client):
  datakey = kms_client.generate_data_key(KeyId=KMS_SYMMETRIC_KEY_ID, KeySpec='AES_128')['Plaintext']

  assert len(datakey) == 128/8
  print("Data key generation test passed")

def test_generate_data_key_pair(kms_client):
  private_key = kms_client.generate_data_key_pair(KeyId=KMS_SYMMETRIC_KEY_ID, KeyPairSpec='RSA_2048')['PrivateKeyPlaintext']

  assert 1200 < len(private_key) < 1250
  print("Data key pair generation test passed")

def test_derive_shared_secret(kms_client):
  public_key = kms_client.get_public_key(KeyId=KMS_ASYMMETRIC_KEY_ID)['PublicKey']
  resp = kms_client.derive_shared_secret(KeyId=KMS_ASYMMETRIC_KEY_ID, KeyAgreementAlgorithm='ECDH', PublicKey=public_key)
  shared_secret = resp['SharedSecret']

  assert len(shared_secret) == 32
  print("Shared secret derivation test passed")

def test_generate_random(kms_client):
    random = kms_client.generate_random(NumberOfBytes=32)['Plaintext']
    assert len(random) == 32
    print("Generate random test passed")

def main():
  kms_endpoint = os.environ.get('AWS_KMS_ENDPOINT')
  client = boto3.client("kms", endpoint_url=kms_endpoint)

  test_decrypt(client)
  test_generate_data_key(client)
  test_generate_data_key_pair(client)
  test_derive_shared_secret(client)
  #test_generate_random(client)

if __name__ == '__main__':
    main()
