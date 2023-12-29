import binascii
import json
import os
import socket
from eth_utils import to_checksum_address
import sha3

from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

import base64
import subprocess
import random
import string

from mnemonic import Mnemonic
from bip32 import BIP32

import struct



def kms_call(credential, ciphertext):
    aws_access_key_id = credential["access_key_id"]
    aws_secret_access_key = credential["secret_access_key"]
    aws_session_token = credential["token"]

    subprocess_args = [
        "/enclave/kms/kmstool_enclave_cli",
        "decrypt",
        "--region",
        os.getenv('REGION'),
        "--proxy-port",
        "8000",
        "--aws-access-key-id",
        aws_access_key_id,
        "--aws-secret-access-key",
        aws_secret_access_key,
        "--aws-session-token",
        aws_session_token,
        "--ciphertext",
        ciphertext,
    ]

    proc = subprocess.Popen(subprocess_args, stdout=subprocess.PIPE)

    # returns b64 encoded plaintext
    result_b64 = proc.communicate()[0].decode()
    plaintext_b64 = result_b64.split(":")[1].strip()

    return plaintext_b64


def send_aws_request_to_ec2(request_type, payload):
    print(f'Received request to send to API for relay: \n{request_type} \n with payload:\n{payload}')
    RELAY_CID = 4294967295
    PORT = 5011

    print(f"checking if payload has message")
    if 'message' in payload.keys():
        print(f'Checking if payload message is bytes')
        if isinstance(payload['message'], bytes):
            payload['message'] = base64.b64encode(
                payload['message']).decode('utf-8')

    request_data = {
        'request_type': request_type,
        'payload': payload
    }

    env = os.environ.get('ENVIRONMENT', 'dev')

    if env == 'dev':
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('127.0.0.1', PORT))
            print('sending to socket')
            s.sendall(json.dumps(request_data).encode('utf-8') + b"$$$")
            response = b""
            termination_sequence = b"$$$"
            while True:
                chunk = s.recv(1024)
                response += chunk
                if termination_sequence in chunk:
                    break
            response = response[:-3]
    else:
        print(f'Connecting to production vsock server')
        try:
            with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as s:
                s.connect((RELAY_CID, PORT))
                print(f'Connection successful, sending request')
                s.sendall(json.dumps(request_data).encode('utf-8') + b"$$$")
                response = b""
                termination_sequence = b"$$$"
                print(f'Awaiting response from socket')
                while True:
                    chunk = s.recv(1024)
                    response += chunk
                    if termination_sequence in chunk:
                        break
                response = response[:-3]
        except socket.error as e:
            print(f'Socket error: {e}')
        except Exception as e:
            print(f'Aws request Error: {e}')

    print(f'Checking response from socket: {response}')
    response = json.loads(response.decode('utf-8'))['result']
    decrypted_response = kms_call(response['credentials'], response['secret'])
    print(f'Decrypted response:{decrypted_response}')
    base64_decoded = base64.b64decode(decrypted_response)

    print(f'Returning response aws_request')
    return base64_decoded

def sign_bytes(bytes_to_sign):
    private_key_data = send_aws_request_to_ec2("get_secret", {"secret_name": os.getenv('SECRET')})
    print(f'Private key data:{private_key_data}')
    private_key = load_pem_private_key(private_key_data, password=None, backend=default_backend())
    
    print(f'Private key loaded:{private_key}')
    # Sign the bytes using the private key
    print(f'Bytes to sign:{bytes_to_sign}')
    signature = private_key.sign(base64.b64decode(bytes_to_sign), ec.ECDSA(hashes.SHA256()))

    print(f'Bytes have been signed: {signature}')
    
    return signature
    

def enclave_server():
    print(f'Starting enclave server')
    ENCLAVE_CID = 20
    PORT = 5010

    env = os.environ.get('ENVIRONMENT', 'dev')

    print(f'Checking environment if dev or prod')
    if env == 'dev':
        print(f'Setup for dev')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', PORT))
    else:
        print(f'Setup for prod')
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.bind((ENCLAVE_CID, PORT))
    s.listen()

    print(f'Starting server loop')
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
                received_data = received_data[:-3]

                try:
                    data_dict = json.loads(received_data.decode('utf-8'))
                    print(f'Incoming request: {data_dict}')

                    print(f'Generating data structures')
                    signed_bytes = sign_bytes(data_dict['bytes'])

                    print("Preparing response")
                    response_json = {
                        "success": "True",
                        "data": "0x"+signed_bytes.hex()
                    }
                    print(f'Response: {response_json}')
                except Exception as e:
                    print(f'TheresAnError: {e}')
                    response_json = {
                        "success": "False",
                        "error": f"Error: {e}"
                    }
                response_data = json.dumps(response_json)
                response = response_data.encode('utf-8')

                conn.sendall(response+b"$$$")
        except KeyboardInterrupt:
            s.close()
            break


if __name__ == "__main__":
    enclave_server()

