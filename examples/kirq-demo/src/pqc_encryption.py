import oqs

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import json
import base64

# Get the current directory of the script
import os
current_dir = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.join(current_dir, '../', 'data')


def load_json(filepath):
    json_file = None
    with open(filepath, 'r') as f:
        try:
            json_file = json.load(f)
        except json.JSONDecodeError:
            raise ValueError("File contains invalid JSON")
    return json_file


def generate_client(client_type, kem_alg="Kyber512", filepath=data_path):
    filepath = os.path.join(filepath, f"{client_type}_secret_key.json")
    client_keys = load_json(filepath)
    if client_keys is None:
        client = oqs.KeyEncapsulation(kem_alg)
        public_key_client = client.generate_keypair()
        secret_key_client = client.export_secret_key()

        # Encode base 64
        public_key_sender_b64 = base64.b64encode(public_key_client).decode('utf-8')
        secret_key_sender_b64 = base64.b64encode(secret_key_client).decode('utf-8')

        combined_data = {'public_key': public_key_sender_b64,
                         'secret_key': secret_key_sender_b64}

        # Write the combined data back to the file
        with open(filepath, 'w') as json_file:
            json.dump(combined_data, json_file, indent=4)
        print(f'Client {client_type} created and saved.')
    else:
        secret_key_client = base64.b64decode(client_keys['secret_key'])
        client = oqs.KeyEncapsulation(kem_alg, secret_key_client)
    return client


def load_client(client_type, filepath=data_path):
    filename = os.path.join(filepath, f"{client_type}_secret_key.json")
    keys_client = load_json(filename)

    public_key_client = keys_client['public_key']
    secret_key_client = keys_client['secret_key']

    public_key_sender = base64.b64decode(public_key_client)
    secret_key_sender = base64.b64decode(secret_key_client)

    return public_key_sender, secret_key_sender


def get_pqc_encryption(message, kem_algo="Kyber512", filepath=data_path):
    sender = generate_client('sender', kem_algo)
    generate_client('receiver', kem_algo)

    # Encapsulate a secret using the recipient's public key
    public_key_receiver, _ = load_client("receiver", filepath)
    cyphertext, shared_secret_sender = sender.encap_secret(public_key_receiver)

    cipher = AES.new(shared_secret_sender[:16], AES.MODE_CBC)
    cyphertext_message = cipher.encrypt(pad(message, AES.block_size))

    # Send cyphertext and encrypted message
    message_package = {
        'cyphertext': base64.b64encode(cyphertext).decode('utf-8'),
        'encrypted_message': base64.b64encode(cyphertext_message).decode('utf-8'),
        'iv': base64.b64encode(cipher.iv).decode('utf-8'),
        'algo': kem_algo,
    }

    return message_package


def get_pqc_decryption(message_package, filepath=data_path):
    _, secret_key_receiver = load_client("receiver", filepath)

    # Assume message_package is received from Client A
    cyphertext = message_package['cyphertext']
    encrypted_message = message_package['encrypted_message']
    iv = message_package['iv']
    kemalg = message_package['algo']

    cyphertext = base64.b64decode(cyphertext)
    encrypted_message = base64.b64decode(encrypted_message)
    iv = base64.b64decode(iv)

    # Decapsulate the shared secret using receiver's private key and KEM cyphertext
    receiver = oqs.KeyEncapsulation(kemalg, secret_key_receiver)
    shared_secret_receiver = receiver.decap_secret(cyphertext)

    # Decrypt the message using the shared secret
    cipher = AES.new(shared_secret_receiver[:16], AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)

    return decrypted_message.decode()
