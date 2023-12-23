import json
import socket
import base64

def send_request_to_enclave(data):
    ENCLAVE_CID = 20  
    PORT = 5010
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.connect((ENCLAVE_CID, PORT))
    s.sendall(json.dumps(data).encode('utf-8') + b"$$$")
    response = b""
    termination_sequence = b"$$$"
    while True:
        chunk = s.recv(1024)
        response += chunk
        if termination_sequence in chunk:
            break
    response = response[:-3]  # remove the termination sequence
    return json.loads(response.decode('utf-8'))

if __name__ == "__main__":
    # Example request to sign some bytes
    message_bytes = b"Hello, sign this message!"
    request_data = {
        "bytes": base64.b64encode(message_bytes).decode('utf-8')
    }
    response = send_request_to_enclave(request_data)
    print(response)
