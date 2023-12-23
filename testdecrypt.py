import boto3

def get_secret(secret_name, region_name):
    """
    Retrieve a secret value from AWS Secrets Manager
    """
    client = boto3.client('secretsmanager', region_name=region_name)
    response = client.get_secret_value(SecretId=secret_name)

    print(f'Response: {response}')
    
    if 'SecretBinary' in response:
        secret = response['SecretBinary']
        return secret
    else:
        return None

def decrypt_with_kms(ciphertext_blob, region_name, key_id=None):
    """
    Decrypt a ciphertext blob using AWS KMS
    """
    client = boto3.client('kms', region_name=region_name)
    response = client.decrypt(CiphertextBlob=ciphertext_blob, KeyId='arn:aws:kms:eu-central-1:665309014761:key/cbeed358-9ada-4189-8ca3-e4b0d203723b')
    return response['Plaintext']

def main():
    region = "eu-central-1"  # Change this to your desired region
    secret_name = "521ec"
    
    # Fetch the secret
    secret_value = get_secret(secret_name, region)
    if secret_value is None:
        print("Failed to fetch the secret.")
        return
    
    # Convert the secret string to bytes (assuming it's base64 encoded)
    ciphertext_blob = secret_value

    print(f'Ciphertextblob: {ciphertext_blob}')
    
    # Decrypt the secret with KMS
    decrypted_secret = decrypt_with_kms(ciphertext_blob, region)
    print("Decrypted Secret:", decrypted_secret)

if __name__ == "__main__":
    main()
