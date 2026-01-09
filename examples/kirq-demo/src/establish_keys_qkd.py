from pathlib import Path
import base64

# Global variable to store simulated keys
shared_key_data = {}

import json

# Get the current directory of the script
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.join(current_dir, '../', 'data')
certificate_path = os.path.join(current_dir, '../', 'certificate')

import sys

# Assuming 'other_code' is the directory you want to import from
etsi_code_path = os.path.join(current_dir, '../')
sys.path.append(etsi_code_path)

from ETSI014.etsi014 import get_key_id_alice, get_key_bob


def save_keys_to_json(filename, new_data):
    print('Save keys into a JSON file.')

    # Check if file exists and read existing data
    if os.path.exists(filename):
        with open(filename, 'r') as json_file:
            try:
                existing_data = json.load(json_file)
            except json.JSONDecodeError:
                existing_data = []
    else:
        existing_data = []

    # Ensure that both `existing_data` and `new_data` are lists
    if not isinstance(existing_data, list):
        raise ValueError("Existing data in JSON is not a list")

    if not isinstance(new_data, list):
        raise ValueError("New data should be provided as a list")

    # Append new data to existing data
    combined_data = existing_data + new_data

    # Write the combined data back to the file
    with open(filename, 'w') as json_file:
        json.dump(combined_data, json_file, indent=4)


def file_exists(filename):
    return Path(filename).exists()


def get_keys_alice(num_keys=10, size=256, option='qkd_sim', **kwargs):
    '''
    Generate multiple keys on Alice's side of the QKD systems.

    :param num_keys: number of keys to generate, by default 10.
    :param size: size of each key in bits, by default 256.
    :param option: 'qkd_sim' or 'qkd', for simulation, or with a real qkd system.
    :return: list of dictionaries with key_ID and key in hexadecimal format.
    '''

    if option == 'qkd_sim':
        global shared_key_data

        keys_list = []
        for _ in range(num_keys):
            # Generate a random key of specified size in bits and convert it to hex
            num_bytes = size // 8  # Convert bits to bytes
            random_key = os.urandom(num_bytes)  # Generate random bytes
            hex_key = random_key.hex().upper()  # Convert bytes to hexadecimal string

            key_id = os.urandom(16).hex()  # Generate a random ID for the key

            shared_key_data[key_id] = hex_key

            keys_list.append({
                "key_ID": key_id,
                "key": hex_key
            })
        file_path = kwargs.get('file_path', f'{data_path}/{option}_keys.json')
        save_keys_to_json(file_path, keys_list)

        return keys_list

    elif option == 'qkd_real':

        kme_hostname = "192.168.101.202"
        client_cert = os.path.join(certificate_path, 'IDQ', "ETSIA.pem")
        client_key = os.path.join(certificate_path, 'IDQ', "ETSIA-key.pem")
        root_ca = os.path.join(certificate_path, 'IDQ', "chrisCA.pem")
        sae_id = "ETSIB"
        force_insecure = True

        str_key, key_id = get_key_id_alice(kme_hostname, client_cert, client_key,
                                           root_ca, sae_id, force_insecure,
                                           **kwargs)

        # Decode the base64 string to bytes
        decoded_bytes = base64.b64decode(str_key)

        # Convert the bytes to a hexadecimal string
        hex_key = decoded_bytes.hex()

        key_info = {
            "key_ID": key_id,
            "key": hex_key
        }
        return [key_info]

    elif option == 'basejump_qkd':

        kme_hostname = "192.168.0.101"
        client_cert = os.path.join(certificate_path, 'Basejump', "USER_001.pem")
        client_key = os.path.join(certificate_path, 'Basejump', "decrypted_USER_001-key.pem")
        root_ca = os.path.join(certificate_path, 'Basejump', "evq-root.pem")
        sae_id = "eq1"
        password = 'basejump'
        force_insecure = True

        str_key, key_id = get_key_id_alice(kme_hostname, client_cert, client_key,
                                           root_ca, sae_id, force_insecure=force_insecure,
                                           **kwargs)

        # Decode the base64 string to bytes
        decoded_bytes = base64.b64decode(str_key)

        # Convert the bytes to a hexadecimal string
        hex_key = decoded_bytes.hex()

        key_info = {
            "key_ID": key_id,
            "key": hex_key
        }
        return [key_info]

    else:

        raise ValueError("Invalid Encryption Option Provided")


def get_key_by_id(key_list, key_id):
    for item in key_list:
        if item['key_ID'] == key_id:
            key = item['key']
            print(f'Corresponding key found : {key}')
            return key
    print(f'key_id : {key_id} not found in data.')
    return None  # Return None if the key_id is not found


def get_key_bob_from_id(key_id=None, option='qkd_sim', **kwargs):
    '''
    Get a key on Bob's side of the QKD systems based on the provided key_id.

    :param key_id: identification number of the key from Alice's side.
    :param option: 'qkd_sim' or 'qkd', for simulation, or with a real qkd system.
    :return: dictionary with key_ID and corresponding key in hexadecimal format.
    '''

    def read_keys_from_file(file_path):
        ''' Helper function to read keys from file '''
        if not os.path.exists(file_path):
            return None

        with open(file_path, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                raise ValueError("File contains invalid JSON")

    if option == 'qkd_sim':
        # Check file if local variable does not have it
        file_path = kwargs.get('file_path', f'{data_path}/{option}_keys.json')

        if file_exists(file_path):
            print('Retrieving keys from file.')
            key_list = read_keys_from_file(file_path)
            return get_key_by_id(key_list, key_id)
        else:
            print('Retrieving keys from global variable.')
            global shared_key_data
            return get_key_by_id(shared_key_data, key_id)

    elif option == 'qkd_real':

        str_key = get_key_bob(key_id, **kwargs)

        # Decode the base64 string to bytes
        decoded_bytes = base64.b64decode(str_key)

        # Convert the bytes to a hexadecimal string
        hex_key = decoded_bytes.hex()

        return hex_key

    elif option == 'basejump_qkd':

        kme_hostname = "192.168.101.102"
        client_cert = os.path.join(certificate_path, 'Basejump', "USER_002.pem")
        client_key = os.path.join(certificate_path, 'Basejump', "decrypted_USER_002-key.pem")
        root_ca = os.path.join(certificate_path, 'Basejump', "evq-root.pem")
        password = 'basejump'
        sae_id = "bellevue"
        force_insecure = True
        print(kwargs)
        str_key = get_key_bob(key_id, kme_hostname, client_cert, client_key,
                              root_ca, sae_id, force_insecure,
                              **kwargs)

        # Decode the base64 string to bytes
        decoded_bytes = base64.b64decode(str_key)

        # Convert the bytes to a hexadecimal string
        hex_key = decoded_bytes.hex()

        return hex_key

    else:
        raise NotImplementedError(f"Option {option} decryption not implemented yet")


# Example usage:
if __name__ == "__main__":
    option = 'basejump_qkd'

    print("Generating multiple keys on Alice's side:")

    alice_keys_response = get_keys_alice(option=option)

    print(alice_keys_response)

    # Selecting the first generated key's ID for demonstration purposes
    selected_key_id = alice_keys_response[0]['key_ID']

    print("\nFetching Bob's Key using selected Key ID:")

    bob_data = get_key_bob_from_id(selected_key_id, option=option)

    print(bob_data)
