from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from pqc_encryption import get_pqc_decryption
from establish_keys_qkd import get_key_bob_from_id

# Get the current directory of the script
import os
current_dir = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.join(current_dir, '../', 'data')


def get_decryption_inputs(option):
    if 'qkd' in option:
        key_id = input("Enter the key ID: ")
        cypher_hex = input("Enter the encrypted message (hex): ")
        return {'key_id': key_id, 'cypher_hex': cypher_hex}

    elif option == 'pqc':
        encrypted_message = input("Enter the encrypted message (hex): ")
        cyphertext = input("Enter the cyphertext: ")
        iv = input("Enter the IV: ")
        kem_algo = input("Enter the algo: ")

        return {
            'encrypted_message':encrypted_message.encode(),
            'cyphertext': cyphertext.encode(),
            'iv': iv.encode(),
            'algo': kem_algo,
        }
    return None

def manual_text_decryption(option='qkd_sim', **inputs):
    # outdated : add it in a separate file for manual decryption
    if inputs is None:
        inputs = get_decryption_inputs(option)
    if option == 'qkd_sim':
        key = get_key_bob_from_id(inputs['key_id'], option=option)
        message = decrypt_received_message(option=option, cypher_hex=inputs['encrypted_message'], key_hex=key)
        return message

    elif option == 'pqc':
        message = decrypt_received_message(option='pqc', **inputs)
        return message

    else:
        raise NotImplementedError(f"Option {option} not implemented yet.")

def decrypt_received_message(option='qkd_sim', **kwargs):
    try:
        if 'qkd' in option:
            cypher_hex, key_hex = kwargs['cypher_hex'], kwargs['key_hex']
            # Convert hex strings back to bytes
            cypher_bytes = bytes.fromhex(cypher_hex)
            aes_key = bytes.fromhex(key_hex)

            # Initialize AES cipher for decryption in ECB mode
            cipher = AES.new(aes_key, AES.MODE_ECB)

            # Decrypt the cyphertext and unpad it
            decrypted_bytes = cipher.decrypt(cypher_bytes)
            message = unpad(decrypted_bytes, AES.block_size).decode()

            print('Message decrypted successfully!')
            return message

        elif option == 'pqc':
            filepath = kwargs.get('filename', data_path)
            message = get_pqc_decryption(kwargs, filepath)

            print('Message decrypted successfully!')
            return message

        else:
            raise NotImplementedError(f'Option {option} not implemented.')

    except KeyError as e:
        print(f'Missing required decryption key: {e}')
    except ValueError as e:
        print(f'Decryption error: {e}')
    except Exception as e:
        print(f'An unexpected error occurred: {e}')



def display_decryption_choice():
    choices = {
        '1': 'pqc',
        '2': 'qkd_sim',
        '3': 'qkd_real',
    }
    while True:
        print("Choose a decryption method:")
        print("1. PQC (local)")
        print("2. Simulated QKD (local)")
        print("3. Real QKD (remote)")
        choice = input("Enter your choice (1, 2 or 3): ")
        if choice in choices:
            return choices[choice]
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    option = display_decryption_choice()
    message = manual_text_decryption(option)
    print("=" * 50)
    print("Decrypted Message:", message)