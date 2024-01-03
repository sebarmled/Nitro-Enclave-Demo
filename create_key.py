import boto3
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import sys
import os

if len(sys.argv) != 3:
    print("Usage: python create_key.py <kms_key_arn> <secret_name>")
    sys.exit(1)

kms_key_id = sys.argv[1]
secret_name = sys.argv[2]

# Initialize boto3 clients
kms_client = boto3.client('kms',os.getenv('REGION'))
secrets_client = boto3.client('secretsmanager',os.getenv('REGION'))

# Step 1: Generate an EC 521 private key
print(f'Generating private key')
private_key = ec.generate_private_key(ec.SECP521R1())
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Step 2: Encrypt the private key using a KMS key
print(f'Encrypting private key')
response = kms_client.encrypt(
    KeyId=kms_key_id,
    Plaintext=private_key_pem
)
encrypted_private_key = response['CiphertextBlob']

print(f'Storing key in Secrets manager')
# Step 3: Store the encrypted private key in AWS Secrets Manager
secrets_client.create_secret(
    Name=secret_name,
    SecretBinary=encrypted_private_key,
    Description='Encrypted EC 521 private key'
)

print(f"Encrypted private key stored in Secrets Manager under the name: {secret_name}")
