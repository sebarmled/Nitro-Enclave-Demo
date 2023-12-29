import base64
import binascii
import boto3
import os
import json
import logging
import sys

from http import client
from http.server import BaseHTTPRequestHandler, HTTPServer

import socket

if not os.getenv('REGION'):
    print('Please define region environment variable')
    sys.exit(0)

if not os.getenv('SECRET'):
    print('Please define secret environment variable')
    sys.exit(0)
    

"""
Setup AWS clients
"""
secrets_manager_client = boto3.client(
    service_name="secretsmanager", region_name=os.getenv("REGION"))
kms_client = boto3.client(
    service_name="kms", region_name=os.getenv("REGION"))


def get_aws_session_token():
    try:
        # Fetch the token
        http_ec2_client = client.HTTPConnection("169.254.169.254")
        headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
        http_ec2_client.request("PUT", "/latest/api/token", headers=headers)
        r = http_ec2_client.getresponse()
        token = r.read().decode()
        # Use the token to fetch the IAM role
        headers = {"X-aws-ec2-metadata-token": token}
        http_ec2_client.request(
            "GET", "/latest/meta-data/iam/security-credentials/", headers=headers)
        r = http_ec2_client.getresponse()
        instance_profile_name = r.read().decode()
        # Fetch the credentials using the IAM role
        http_ec2_client.request(
            "GET",
            f"/latest/meta-data/iam/security-credentials/{instance_profile_name}",
            headers=headers,
        )
        r = http_ec2_client.getresponse()
        resp_r = r.read()
        response = json.loads(resp_r)
        # Extract the credentials
        credential = {
            "access_key_id": response["AccessKeyId"],
            "secret_access_key": response["SecretAccessKey"],
            "token": response["Token"],
        }
        return credential
    except client.HTTPException as e:
        raise Exception(f"HTTP error occurred: {e}")
    except json.JSONDecodeError as e:
        raise Exception(f"Error decoding JSON: {e}")
    except Exception as e:
        raise Exception(f"An error occurred: {e}")


def get_secret(secret_name):
    """
    Retrieve a secret from AWS Secrets Manager.
    """
    try:
        print(f'Get::Getting secret: {secret_name}')
        response = secrets_manager_client.get_secret_value(
            SecretId=secret_name)
        print(f'Get::Response from secret manager: {response}')
        secret = response.get("SecretString",response.get("SecretBinary",None))
        print(f'Get::Secret: {secret}')
        credentials = get_aws_session_token()
        print(f'Get::Response from credentials fetch: {credentials}')

        return {
            'secret': secret,
            'credentials': credentials,
        }
    except Exception as e:
        logging.error(f"Error retrieving secret {secret_name}: {e}")
        return None


def sign_with_kms_private_key(key_name: str, message: bytes) -> bytes:
    """
    Sign a message using a private key stored in AWS KMS.

    Args:
    - key_name (str): The identifier for the CMK in KMS.
    - message (bytes): The message to sign.

    Returns:
    - bytes: The signature.
    """

    kms_client = boto3.client('kms')

    response = kms_client.sign(
        KeyId=key_name,
        Message=message,
        MessageType='RAW',
        # ECDSA with SHA-256 algorithm
        SigningAlgorithm='ECDSA_SHA_256'
    )

    # Return the signature
    return response['Signature']


def relay_enclave_aws_request(data):
    print(f"Relay::Received request: {data}")
    request_type = data['request_type']
    payload = data['payload']

    if request_type == "get_secret":
        print(f'Relay::Getting secret: {payload["secret_name"]}')
        secret_name = payload['secret_name']
        secret_value = get_secret(secret_name)
        return {'result': secret_value}

    elif request_type == "sign_with_kms":
        key_name = payload['key_name']
        message = payload['message']
        signature = sign_with_kms_private_key(key_name, message)
        return {'result': signature}

    else:
        return {'error': 'Invalid request type'}


def vsock_server():
    RELAY_CID = 4294967295
    PORT = 5011
    env = os.environ.get('ENVIRONMENT', 'dev')

    print(f'Checking environment if dev or prod')
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.bind((RELAY_CID, PORT))

    print(f'Listening on port {PORT}')
    s.listen()

    print(f'Starting loop')
    while True:
        try:
            conn, addr = s.accept()
            with conn:
                received_data = b""
                termination_sequence = b"$$$"
                while True:
                    chunk = conn.recv(1024)
                    received_data += chunk
                    if termination_sequence in chunk:
                        break
                # Remove the termination sequence
                received_data = received_data[:-3]

                request_data = json.loads(received_data.decode('utf-8'))

                payload = request_data.get('payload')
                try:
                    payload_bytes = base64.b64decode(payload)
                    request_data['payload'] = payload_bytes
                except (binascii.Error, TypeError):
                    pass

                response_data = relay_enclave_aws_request(request_data)

                print(f'Relay::Response data: {response_data}')

                if isinstance(response_data['result']['secret'], bytes):
                    response_data['result']['secret'] = base64.b64encode(
                        response_data['result']['secret']).decode('utf-8')

                response = json.dumps(response_data).encode('utf-8')
                conn.sendall(response + b"$$$")
        except Exception as e:
            print(f'Exception in relay server: {e}')


if __name__ == "__main__":
    vsock_server()
