import boto3
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Initialize boto3 clients
kms_client = boto3.client('kms','eu-central-1')
secrets_client = boto3.client('secretsmanager','eu-central-1')

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
kms_key_id = 'arn:aws:kms:eu-central-1:665309014761:key/cbeed358-9ada-4189-8ca3-e4b0d203723b'  # Replace with your KMS key ID
response = kms_client.encrypt(
    KeyId=kms_key_id,
    Plaintext=private_key_pem
)
encrypted_private_key = response['CiphertextBlob']

print(f'Storing key in Secrets manager')
# Step 3: Store the encrypted private key in AWS Secrets Manager
secret_name = '521ec'
secrets_client.create_secret(
    Name=secret_name,
    SecretBinary=encrypted_private_key,
    Description='Encrypted EC 521 private key'
)

print(f"Encrypted private key stored in Secrets Manager under the name: {secret_name}")
