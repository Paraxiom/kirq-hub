from emails import read_email
from pqc_encryption import get_pqc_decryption
from establish_keys_qkd import get_key_bob_from_id
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

import functools

import os
current_dir = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.join(current_dir, '../', 'data')

import sys
# Assuming 'other_code' is the directory you want to import from
etsi_code_path = os.path.join(current_dir, '../')
sys.path.append(etsi_code_path)

from ETSI014.etsi014 import get_key_bob

def email_decryption(f):
    @functools.wraps(f)
    def wrapper(option, *args, **kwargs):
        # Read the email based on option
        if 'qkd' in option:
            if 'real' in option:
                subject = kwargs.get('subject', 'Real QKD encrypted email')
            elif 'basejump' in option:
                subject = kwargs.get('subject', 'QKD via Basejump encrypted email')
            elif 'sim' in option:
                subject = kwargs.get('subject', 'Simulated QKD encrypted email')
        elif option == 'pqc':
            subject = kwargs.get('subject', 'PQC encrypted email')
        else:
            raise NotImplementedError(f'Decryption option {option} not implemented.')
        email_data = read_email(subject=subject, encryption_option=option, **kwargs)
        kwargs.pop('password', None)

        # Merge email data with other kwargs
        kwargs.update(email_data)

        return f(option, *args, **kwargs)

    return wrapper


def qkd_sim_decryption(f):
    @functools.wraps(f)
    def wrapper(option, *args, **kwargs):
        if 'qkd' in option:
            cypher_hex, key_id = kwargs['cypher_hex'], kwargs['key_id']

            hex_key = get_key_bob_from_id(option=option, **kwargs)

            # Convert hex strings back to bytes
            cypher_bytes = bytes.fromhex(cypher_hex)
            aes_key = bytes.fromhex(hex_key)

            # Initialize AES cipher for decryption in ECB mode
            cipher = AES.new(aes_key, AES.MODE_ECB)

            # Decrypt the cyphertext and unpad it
            decrypted_bytes = cipher.decrypt(cypher_bytes)
            message = unpad(decrypted_bytes, AES.block_size).decode()

            return f(option, message=message, *args, **kwargs)
        else:
            return f(option, *args, **kwargs)

    return wrapper


def pqc_decryption(f):
    @functools.wraps(f)
    def wrapper(option, *args, **kwargs):
        if option == 'pqc':
            filepath = kwargs.get('filepath', data_path)
            message = get_pqc_decryption(kwargs, filepath)
            return f(option, message=message, *args, **kwargs)
        else:
            return f(option, *args, **kwargs)

    return wrapper


@email_decryption
@qkd_sim_decryption
@pqc_decryption
def decrypt_received_message(option='qkd_sim', **kwargs):
    message = kwargs.get('message')
    if message:
        print('Message decrypted successfully!')
        print("Decrypted Message:", message)
        return message
    else:
        raise Exception(f'Something went wrong with the decryption {option}, message not decrypted.')


def display_decryption_choice():
    choices = {
        '1': 'pqc',
        '2': 'qkd_sim',
        '3': 'qkd_real',
        '4': 'basejump_qkd',
    }
    while True:
        print("Choose a decryption method:")
        print("1. PQC (local)")
        print("2. Simulated QKD (local)")
        print("3. Real QKD (remote)")
        print("4. Real QKD via Basejump (remote)")
        choice = input("Enter your choice (1, 2, 3 or 4): ")
        if choice in choices:
            return choices[choice]
        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    option = display_decryption_choice()
    decrypt_received_message(option)