# KIRQ Python QKD App - Concatenated Files
# Generated on 2025-03-03 10:34:16



================================================================================
# FILE: src/establish_keys_qkd.py
================================================================================

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


================================================================================
# FILE: src/app.py
================================================================================

import streamlit as st
import re
from demo_send_encrypted_email import get_email_body_and_encrypt, send_email
from demo_decrypt_received_email import decrypt_received_message
from demo_decrypt_message import manual_text_decryption
from help import display_decrypt_text_help, display_decrypting_email_help, display_sending_email_help

import os

# To run the app : streamlit run app.py

import base64

# Encode the image into base64
def get_base64_image(image_path):
    with open(image_path, "rb") as img_file:
        return base64.b64encode(img_file.read()).decode()


# Get the current directory of the script
current_dir = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.join(current_dir, '../', 'data')

choices = {
        # "Real QKD": 'QKD',
        "Simulated QKD": 'qkd_sim',
        "Real QKD": 'qkd_real',
        "QKD via Basejump": "basejump_qkd",
        "PQC": "pqc"
    }


# Main navigation options
def main():
    # Set the page config with a custom title
    st.set_page_config(
        page_title="Quantum Safe Email",
        page_icon="🔐",
        layout="centered",  # other options: "wide"
        initial_sidebar_state="auto"  # other options: "expanded", "collapsed"
    )

    # Define CSS for changing the background color
    path_img = os.path.join(data_path, 'Untitled-design.png')
    bg_img = get_base64_image(path_img)
    bg_img_base64 = f"data:image/jpeg;base64,{bg_img}"

    page_bg_img = f"""
    <style>
    [data-testid="stAppViewContainer"] > .main {{
    background-image: url("{bg_img_base64}");
    background-size: cover;
    background-position: center center;
    background-repeat: no-repeat;
    background-attachment: local;
    }}
    [data-testid="stHeader"] {{
    background: rgba(0,0,0,0);
    }}
    </style>
    """

    st.markdown(page_bg_img, unsafe_allow_html=True)

    # Add an image at the top
    logo_path = os.path.join(data_path, 'Logo_officiel_AN-RV.png')
    st.image(logo_path, use_column_width=True)
    st.markdown(
        """
        <div style='text-align: center;'>
            <h1 style="color: #007B8A;">This application is made by Kirq</h1>
            <p style='font-size: 18px; color: #555;'>This is a <b>demonstration*</b> of a Quantum Safe Email application</p>
            <p style="font-size: 10px; color: #555;">
                <i><span style="color: #888888;">*</span>* Do not use this application in a production environment. It is for demonstration purposes only, and using this app might pose security risks.</i>
            </p>
            <a href='https://kirq.numana.tech/en/' style='font-size: 20px; color: #007B8A; text-decoration: none;'>
                🌐 Click here to visit our website
            </a>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Read the SVG file content
    svg_file = os.path.join(current_dir, '../', 'data', 'logo-numana-couleur.svg')
    with open(svg_file, "r") as f:
        svg_content = f.read()

    # Embed the SVG using markdown
    st.sidebar.markdown(
        f"""
        <div align="center">
            {svg_content}
        """,
        unsafe_allow_html=True
    )
    st.sidebar.title(" ")
    st.sidebar.title("Choose Encryption Method")
    encryption_method = st.sidebar.radio("🔐  Select a method:", [choice for choice in choices.keys()])

    st.title("Quantum Safe Email")
    option = st.selectbox("📂 Choose an option:",
                          ["✉️🔐 Sending Encrypted Email", "✉️🔓 Decrypting Email", "📝🔓 Decrypting Text"])

    if option == "✉️🔐 Sending Encrypted Email":
        send_encrypted_email(encryption_method)
    elif option == "✉️🔓 Decrypting Email":
        decrypt_email(encryption_method)
    elif option == "📝🔓 Decrypting Text":
        decrypt_text(encryption_method)


def send_encrypted_email(encryption_method):

    # Two object on the same line
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Send Encrypted Email")
    with col2:
        if st.button("ℹ️ Get Help"):
            display_sending_email_help()

    sender_email = st.text_input("📨 Email of the sender")
    recipient_email = st.text_input("📩 Email of the recipient")
    message = st.text_area("📝 Message to send")
    password = st.text_input("🔒 Password", type="password")

    if st.button("📤 Send"):
        # Here you would call your encryption and email sending functions
        # send_encryption_email(sender_email, recipient_email, message, password, encryption_method)
        # For the purpose of the example, let's simulate this process
    # try:
        option = choices[encryption_method]
        from_email, to_email, encrypted_message_with_metadata = get_email_body_and_encrypt(
            option,
            sender_email,
            message,
            recipient_email,
            file_path=f'{data_path}/{option}_keys.json',
            st=st)

        send_email(from_email, f'{encryption_method} encrypted email',
                   encrypted_message_with_metadata,
                   to_email,
                   password=password,
                   st=st)

        st.write(f"🔑 Sending encrypted email via {encryption_method}...")

        st.success("✅ Email sent successfully!")
        # except Exception as e:
            # st.error(f"❌ An error occurred: {e}")


def decrypt_email(encryption_method):

    # Two object on the same line
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Decrypt Email")
    with col2:
        if st.button("ℹ️ Get Help"):
            display_decrypting_email_help()

    email = st.text_input("📧 Email")
    password = st.text_input("🔒 Password", type="password")

    if st.button("🔓 Decrypt"):
        option = choices[encryption_method]
        try:
            kwargs = {'email':email,
                      'password':password,
                      'subjet':f"{encryption_method} encrypted email"}
            kwargs.update({'st':st})
            decrypted_message = decrypt_received_message(option, **kwargs)
            st.success(f"✅ Decrypted Message: {decrypted_message}")
        except Exception as e:
            st.error(f"❌ An error occurred: {e}")


def metadata_parser(metadata, encryption_method):
    if "QKD" in encryption_method:
        # Extract Key ID (either full formatted or only the ID)
        key_id_match = re.search(r'Key ID:([a-zA-Z0-9]+)', metadata)
        if key_id_match:
            key_id = key_id_match.group(1)
        else:
            # Assume it's just the ID without "Key ID:" prefix
            key_id = metadata.strip()
        return {"key_id": key_id}

    elif encryption_method == "PQC":
        # Extract Cyphertext, IV, and Algorithm
        cyphertext_match = re.search(r'Cyphertext:\s*(.*?)\s*IV:', metadata, re.DOTALL)
        iv_match = re.search(r'IV:\s*(.*?)\s*Algorithm:', metadata, re.DOTALL)
        algorithm_match = re.search(r'Algorithm:\s*(.*)', metadata)

        cyphertext = cyphertext_match.group(1).strip() if cyphertext_match else None
        iv = iv_match.group(1).strip() if iv_match else None
        algorithm = algorithm_match.group(1).strip() if algorithm_match else None

        return {"cyphertext": cyphertext, "iv": iv, "algo": algorithm}
    else:
        raise ValueError("Unsupported encryption method")


def decrypt_text(encryption_method):

    # Two object on the same line
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Decrypt Text")
    with col2:
        if st.button("ℹ️ Get Help"):
            display_decrypt_text_help(encryption_method)

    encrypted_text = st.text_area("🔐 Encrypted Text")
    metadata = st.text_area("📄 Metadata")
    inputs = metadata_parser(metadata, encryption_method)
    inputs.update({'encrypted_message':encrypted_text})

    if st.button("🔓 Decrypt"):
        option = choices[encryption_method]
        try:
            st.write("🛠️ Decrypting text...")
            decrypted_text = manual_text_decryption(option, **inputs)
            st.success(f"✅ Decrypted Text: {decrypted_text}")
        except Exception as e:
            st.error(f"❌ An error occurred: {e}")

# Function to show help based on encryption method


if __name__ == "__main__":
    main()

================================================================================
# FILE: src/demo_send_encrypted_email.py
================================================================================

from establish_keys_qkd import get_keys_alice
from pqc_encryption import get_pqc_encryption
from emails import send_email

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Get the current directory of the script
import os
current_dir = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.join(current_dir, '../', 'data')

def html_cypher_text_qkd(qkd_type, cypher_text_hex, selected_key_id):
    cypher_text_with_meta_data = f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    color: #333333;
                    line-height: 1.6;
                }}
                h1 {{
                    color: #007BFF;
                    text-align: center;
                }}
                .cypher-text {{
                    font-family: 'Courier New', Courier, monospace;
                    background-color: #f9f9f9;
                    border-radius: 5px;
                    padding: 10px;
                    margin-top: 20px;
                }}
                .key-id {{
                    font-weight: bold;
                    color: #FF4500; /* OrangeRed */
                }}
                .note {{
                    font-style: italic;
                    color: #808080; /* Gray */
                }}
                .footer {{
                   text-align:center; 
                   margin-top :20px ;
                   font-size :0.9em ; 

                   color:#666666 ;

                     }}
            </style>
        </head>
        <body>
            <h1>🔐 This message is encrypted using a {qkd_type} system.</h1>
            <div class="cypher-text">
               {cypher_text_hex}
             </div>

         </br>
           <h2 style="color: #8a8a8a;">📄 Metadata</h2>
           <p class="key-id">Key ID:{selected_key_id}</p>

           <p class="note">NB : this message is sent by Alice, to decrypt it, you should get the key via Bob's side of the QKD pair.
    </p>

    <div class="footer">
    <p>From <a href="https://kirq.numana.tech/en/">Kirq</a> by <i>Numana</i></p>       

          </div>



        </body>
        </html >

    """
    return cypher_text_with_meta_data


def html_cypher_text_pqc(message_package):
    cypher_text_with_meta_data = f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    color: #333333;
                    line-height: 1.6;
                }}
                h1 {{
                    color: #007BFF;
                    text-align: center;
                }}
                .cypher-text {{
                    font-family: 'Courier New', Courier, monospace;
                    background-color: #e9e9e9;
                    border-radius: 5px;
                    padding: 10px;
                    margin-top: 20px;
                }}
                .meta-data {{
                    font-family: 'Courier New', Courier, monospace;
                    background-color: #f9f9f9;
                    border-radius: 5px;
                    padding: 10px;
                    margin-top: 20px;
                }}
                .algo-type {{
                    font-weight: bold;
                    color: #FF4500; /* OrangeRed */
                }}
                .note {{
                    font-style: italic;
                    color: #808080; /* Gray */
                }}
                .footer {{
                   text-align: center;
                   margin-top: 20px;
                   font-size: 0.9em;
                   color: #666666;
                }}
            </style>
        </head>
        <body>
            <h1>🔐 This message is encrypted using a PQC algorithm.</h1>
            <div class="cypher-text">
               {message_package['encrypted_message']}
             </div >
            <h2 style="color: #8a8a8a;">📄 Metadata</h2>
            <div class="meta-data">
                <p><strong>Cyphertext:</strong> {message_package['cyphertext']}</p>
                <p><strong>IV:</strong> {message_package['iv']}</p>
            </div>
            <br/>
            <p class="algo-type">Algorithm: {message_package['algo']}</p>
            <p class="note">Note: This message has been encrypted using Post-Quantum Cryptography (PQC). To decrypt it, please use the respective private key.</p>
            <div class="footer">
              <p>From <a href="https://kirq.numana.tech/en/">Kirq</a> by <i>Numana</i></p>
            </div>
        </body>
        </html>
    """
    return cypher_text_with_meta_data


def get_email_inputs():
    from_email = input("Enter your email: ")
    body = input("Type your message: ")
    to_email = input("Recipient email: ")
    return from_email, body, to_email


def get_qkd_sim_encryption(selected_key_info, body):
    key_hex = selected_key_info['key']
    selected_key_id = selected_key_info['key_ID']

    # Convert hex string back to bytes for encryption
    print('type key qkd', type(key_hex))
    aes_key = bytes.fromhex(key_hex)

    # Encrypting message using AES in ECB mode
    cipher = AES.new(aes_key, AES.MODE_ECB)
    padded_body = pad(body.encode(), AES.block_size)
    cypher_text_bytes = cipher.encrypt(padded_body)
    cypher_text_hex = cypher_text_bytes.hex().upper()

    return cypher_text_hex, selected_key_id


def get_email_body_and_encrypt(option='qkd_sim',
                               from_email=None,
                               body=None,
                               to_email=None,
                               **kwargs):
    if from_email is None:
        from_email, body, to_email = get_email_inputs()

    if 'qkd' in option.lower():
        keys_response = get_keys_alice(option=option, **kwargs)
        selected_key_info = keys_response[0]
        print(f"Generated Key Info: {selected_key_info}")

        cypher_text_hex, selected_key_id = get_qkd_sim_encryption(selected_key_info, body)

    elif 'pqc' in option.lower():
        kem_algo = kwargs.get('kem_algo', "Kyber512")
        message_package = get_pqc_encryption(body.encode(), kem_algo=kem_algo)

    algo_type = {
        'qkd_sim': 'simulated QKD',
        'qkd_real': 'real QKD',
        'basejump_qkd': 'QKD via Basejump',
        'pqc': 'PQC'
    }.get(option, 'Unknown')

    print(f"Using {algo_type}")

    if 'qkd' in option.lower():
        cypher_text_with_meta_data = html_cypher_text_qkd(algo_type, cypher_text_hex, selected_key_id)
    elif 'pqc' in option.lower():
        cypher_text_with_meta_data = html_cypher_text_pqc(message_package)
    else:
        raise NotImplementedError(f'Encryption {option} not implemented.')

    return from_email, to_email, cypher_text_with_meta_data


def display_encryption_choice():
    choices = {
        '1': 'pqc',
        '2': 'qkd_sim',
        '3': 'qkd_real',
        '4': 'basejump_qkd',
    }
    while True:
        print("Choose an encryption method:")
        print("1. PQC (local)")
        print("2. Simulated QKD (local)")
        print("3. Real QKD (remote)")
        print("4. Real QKD via Basejump (remote)")
        choice = input("Enter your choice (1, 2, 3, or 4): ")
        if choice in choices:
            return choices[choice]
        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    option = display_encryption_choice()

    from_email, to_email, encrypted_message_with_metadata = get_email_body_and_encrypt(
        option, file_path=f'{data_path}/{option}_keys.json')

    print(f"From Email: {from_email}")
    print(f"Encrypted Message:\n{encrypted_message_with_metadata}")

    send_email(from_email, f'{option.upper()} encrypted email', encrypted_message_with_metadata, to_email)




================================================================================
# FILE: ETSI014/etsi014.py
================================================================================

from etsi_qkd_014_client import QKD014Client
import base64
import os

# Get the current directory of the script
current_dir = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.join(current_dir, '..', 'certificate', 'IDQ')

def get_key_id_alice(kme_hostname="192.168.101.202",
                     client_cert=os.path.join(data_path, "ETSIA.pem"),
                     client_key=os.path.join(data_path, "ETSIA-key.pem"),
                     root_ca=os.path.join(data_path, "chrisCA.pem"),
                     sae_id="ETSIB",
                     password=None,  # Kept for backwards compatibility but not used
                     force_insecure=True,
                     **kwargs):
    st = kwargs.get('st', None)  # Application
    # Create client for Alice
    client_alice = QKD014Client(
        kme_hostname,
        client_cert,
        client_key,
        root_ca,
        force_insecure=force_insecure
    )
    
    if st is not None:
        code, data = client_alice.get_status(sae_id)
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("## 🧘🏽‍♀️ Alice's client 🔐")
            st.write(client_alice)
        with col2:
            st.markdown("### ⚙️ Client's status ")
            st.write(data)
        st.write('... Encrypt key 🐇')
        st.markdown('---')
    else:
        print('Alice :', client_alice)
        
    # Get a key
    code, data = client_alice.get_key(sae_id)  # By default, this request one key of 256 bits
    key_id = data.keys[0].key_id
    key_alice = data.keys[0].key
    if code != 200:
        raise Exception(f"Key encryption failed. Error code {code} : {data}")
    return key_alice, key_id

def get_key_bob(key_id, kme_hostname="192.168.101.207",
             client_cert=os.path.join(data_path, "ETSIB.pem"),
             client_key=os.path.join(data_path, "ETSIB-key.pem"),
             root_ca=os.path.join(data_path, "chrisCA.pem"),
             sae_id="ETSIA",
             password=None,  # Kept for backwards compatibility but not used
             force_insecure=True,
             **kwargs):
    st = kwargs.get('st', None)  # Application
    # Create client for Bob
    client_bob = QKD014Client(
        kme_hostname,
        client_cert,
        client_key,
        root_ca,
        force_insecure=force_insecure
    )
    
    if st is not None:
        code, data = client_bob.get_status(sae_id)
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("## 🧙‍♂️ Bob's client 🔓")
            st.write(client_bob)
        with col2:
            st.markdown("### ⚙️ Client's status ")
            st.write(data)
        st.write('... Decrypt key 🕶️')
        st.markdown('---')
    else:
        print('Bob client : ', client_bob)
        
    # Get key
    print(key_id)
    code, data = client_bob.get_key_with_key_IDs(sae_id, [key_id])
    if code != 200:
        raise Exception(f"Key decryption failed. Error code {code} : {data}")
    key_bob = data.keys[0].key
    return key_bob

# Test with Toshiba QKD system in Sherbrooke
if __name__ == "__main__":
    data_path = os.path.join(current_dir, '..', 'certificate', 'Toshiba', 'certs')
    alice_key = get_key_id_alice(kme_hostname="192.168.0.4",
                     client_cert=os.path.join(data_path, "client_alice_crt.pem"),
                     client_key=os.path.join(data_path, "client_alice_key.pem"),
                     root_ca=os.path.join(data_path, "ca_crt.pem"),
                     sae_id="bobsae")
    print(alice_key)
    bob_key = get_key_bob(alice_key[1], 
                     kme_hostname="192.168.0.2",
                     client_cert=os.path.join(data_path, "client_bob_crt.pem"),
                     client_key=os.path.join(data_path, "client_bob_key.pem"),
                     root_ca=os.path.join(data_path, "ca_crt.pem"),
                     sae_id="alicesae")
    print(bob_key)


================================================================================
# FILE: src/demo_decrypt_message.py
================================================================================

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

================================================================================
# FILE: src/demo_decrypt_received_email.py
================================================================================

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

================================================================================
# FILE: src/pqc_encryption.py
================================================================================

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


================================================================================
# FILE: src/help.py
================================================================================

import streamlit as st


@st.dialog("ℹ️ Get help")
def display_decrypt_text_help(encryption_method):
    if "QKD" in encryption_method:
        st.title("Help for QKD Encryption")
        st.markdown(
            """
            <div style='text-align: left;'>
                <h2>Key generated using QKD (Quantum Key Distribution)</h2>
                <p>For keys using QKD, you need to provide the <b>Key ID</b> from the received metadata.</p>
                <h3>Example:</h3>
                <p> 1. First get the cyphertext received in the light gray box, and copy paste it in the appropriate text box.</p>
                <pre><code>D8749DE1E2F359DD8E107C1D5D5592EA</code></pre>
                <p> 2. Then you should copy paste the metadata section, containing the key ID.</p>
                <p>Full Key ID:</p>
                <pre><code>Key ID:35e8293061c68ceb7a20c17d85174bd8</code></pre>
                <p>Or you can just copy paste the ID directly :</p>
                <pre><code>35e8293061c68ceb7a20c17d85174bd8</code></pre>
                <p>Copy the metadata received in the email and paste it in the appropriate field.</p>
            </div>
            """,
            unsafe_allow_html=True
        )
    elif encryption_method == "PQC":
        st.title("Help for PQC Encryption")
        st.markdown(
            """
            <div style='text-align: left;'>
                <h2>PQC (Post-Quantum Cryptography)</h2>
                <p>For PQC, you need to provide the full metadata, which includes:</p>
                <ul>
                    <li><b>Cyphertext</b></li>
                    <li><b>IV (Initialization Vector)</b></li>
                    <li><b>Algorithm</b></li>
                </ul>
                <h3>Example:</h3>
                <pre><code>
                    Cyphertext: CM4zbcGaK9dATSHPvOI8VZExYQPzHfazuF/0UnYg8DTmgwMNxjREs7PMDgL3gU8VaRI9aqY/pguFhWnIYcIoJAL7IJ/xMIJdiuWhqrLyV1L4y1Ldy8nea0USZAU1PsrjfyOnSIKPzMFIw8+GZewAMz9qTBCmi700SqNWspshadG0vKCiRqJm0ezmQ6mZeckIDlTe4K0dPa77sAvmMhbRKPlRodP1E5eY6V7rHz5Conveq4Cu0EuVTFe9kcMIeSF5d/wPCipOo+IJepNfMr04qwLJKmaSmvXFGaAnEp0FNCZk/1dao1cbQwKnxNWCj/j2eXF7AWXyb2j8kEU6eiak+EbRxdY0/wvZYtWVAz2QdBk3TsM6BOTxhAqNI3VY0qCQDOpL9vps1u65zd2xDOB3r04poXbQHaYKMnXLnmrd5PlD+0/ZIsDLMvnvT/z/SEHDIsZEMpPyzutfjgyWrfah05l3UL9QpXwXnMCyKnjlL/h+l2GMRCazBvoiQ46sJNMiUwnOUmbyxvCkH/gxavin/nx9u7Lg48r1kPuuBbN8hoXbuboDpdsfoEN4M5EAGluyzmxAaBE/8n/yNDFSWHFfTDBUAIQYedjyCx+tYhgpYlMwTPqwVhlInGZYw4B/R2/oQXtAw6+aCWJqZpDdTTBFJYoG2tvYZe7j85MWxUfQYhhIuzx2Z3IouMYXKqdovtE/ZzcWMk39PCCx00dVjbfseFVfe0nHLQGCDeSn6FE9XAahyEJI4YvSQvQeNVnOhUAB7ggLCib9Gfn4/yaTIoobrmrRsTczpsQY4y0AAH7ssPEf6UraoLIDfy2WiACZE5kr72sySmdRnyMJ92I7pPiBzdIRYFTjIYZmitkZ3fHxDGP9XI/JWOQk5qIqqHliSJORkRgmgRgLLAJ+oRQPzZ2SX8A16y+irmG1ExtsjO2zxxnZACFmTL9TNeEuN5EillICqvFnLsuQDzlujH112Ple5+4wTsCSuECOH/E8Z1800gifi1zHgXQCapYeLAhSvFNY
                    IV: gNdYK2PQIqvYZTLOZ2dTEA==
                    Algorithm: Kyber512
                </code></pre>
                <p>Copy the metadata received in the email and paste it in the appropriate field.</p>
            </div>
            """,
            unsafe_allow_html=True
        )


@st.dialog("ℹ️ Get help")
def display_sending_email_help():
    st.title("Help for Sending Emails")

    st.markdown(
        """
        <div style='text-align: left;'>
            <h2>Sending Emails with Outlook and Gmail</h2>
            <p>To send emails using this application, you must create an <b>application-specific password</b> for your email account. Standard account passwords will not work.</p>
            <h3>Creating an Application Password</h3>
            <p>Follow the steps below to generate an application-specific password for your email provider:</p>
            <h4>Gmail</h4>
            <ol>
                <li>Go to your Google Account and sign in.</li>
                <li>Navigate to <a href="https://myaccount.google.com/apppasswords" target="_blank">Google Account Security</a>.</li>
                <li>Under "Signing in to Google," select "App passwords."</li>
                <li>Sign in again if prompted, and then select "Other" and name your app (e.g., "Streamlit App").</li>
                <li>Click "Generate" and copy the 16-character password.</li>
            </ol>
            <p>Use this generated password in the application instead of your usual Gmail password. <b>Standard Gmail passwords will not work.</b></p>
        
            <h3>Important Note</h3>
            <p>Make sure you use the application-specific passwords when setting up email sending in this application. If you use your standard email password, it will not work.</p>
        </div>
        """,
        unsafe_allow_html=True
    )


@st.dialog("ℹ️ Get help")
def display_decrypting_email_help():
    st.title("Help for Decrypting Emails")

    st.markdown(
        """
        <div style='text-align: left;'>
            <h2>Decrypting Emails with Outlook and Gmail</h2>
            <p>To decrypt emails using this application, you must connect using an <b>application-specific password</b> for your email account. Standard account passwords will not work.</p>
            <h3>Creating an Application Password</h3>
            <p>Follow the steps below to generate an application-specific password for your email provider:</p>
            <h4>Gmail</h4>
            <ol>
                <li>Go to your Google Account and sign in.</li>
                <li>Navigate to <a href="https://myaccount.google.com/apppasswords" target="_blank">Google Account Security</a>.</li>
                <li>Under "Signing in to Google," select "App passwords."</li>
                <li>Sign in again if prompted, and then select "Other" and name your app (e.g., "Streamlit App").</li>
                <li>Click "Generate" and copy the 16-character password.</li>
            </ol>
            <p>Use this generated password in the application instead of your usual Gmail password. <b>Standard Gmail passwords will not work.</b></p>
            <h4>Outlook</h4>
            <ol>
                <li>Go to your Microsoft Account and sign in.</li>
                <li>Navigate to <a href="https://mysignins.microsoft.com/security-info" target="_blank">Microsoft Account Security</a>.</li>
                <li>Under "More security options," select "Create a new app password."</li>
                <li>Sign in again if prompted, and then select "Create a new app password."</li>
                <li>Copy the generated password.</li>
            </ol>
            <p>Use this generated password in the application instead of your usual Outlook password. <b>Standard Outlook passwords will not work.</b></p>
            <h3>Important Note</h3>
            <p>Make sure you use the application-specific password when setting up email decryption in this application. If you use your standard email password, it will not work.</p>
            <h3>Alternative Option</h3>
            <p>If you are unable to connect using the application-specific password, you can use the <b>Decrypt Text</b> option provided by the app. Further information and instructions for using <b>Decrypt Text</b> can be found in its associated help menu.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

================================================================================
# FILE: src/emails.py
================================================================================

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import imaplib
import email
from getpass import getpass
from pwinput import pwinput
from bs4 import BeautifulSoup

def get_email_settings(email_address):
    """Determine SMTP and IMAP settings based on email domain."""
    domain = email_address.split('@')[1].lower()
    
    # Common email providers
    providers = {
        'gmail.com': {
            'smtp': 'smtp.gmail.com',
            'smtp_port': 587,
            'imap': 'imap.gmail.com'
        },
        'outlook.com': {
            'smtp': 'smtp.outlook.com',
            'smtp_port': 587,
            'imap': 'imap.outlook.com'
        },
        'hotmail.com': {
            'smtp': 'smtp.outlook.com',
            'smtp_port': 587,
            'imap': 'imap.outlook.com'
        },
        'office365.com': {
            'smtp': 'smtp.office365.com',
            'smtp_port': 587,
            'imap': 'outlook.office365.com'
        },
        'numana.io': {  # Added for Numana
            'smtp': 'smtp.office365.com',
            'smtp_port': 587,
            'imap': 'outlook.office365.com'
        }
    }
    
    # Check if domain is in known providers
    if domain in providers:
        return providers[domain]
    
    # For unknown domains, try to construct smtp/imap addresses
    # Note: This might not work for all providers
    return {
        'smtp': f'smtp.{domain}',
        'smtp_port': 587,  # Common default port
        'imap': f'imap.{domain}'
    }

def send_email(from_email, subject, body, to_email, password=None, st=None):
    if password is None:
        password = pwinput(prompt="Enter your password: ", mask='*')
    
    try:
        # Create the message
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))

        if st is None:
            print("Connecting to SMTP server...")
        else:
            st.write("Connecting to SMTP server...")

        # Get email settings
        settings = get_email_settings(from_email)
        
        try:
            # Try connecting to SMTP server
            server = smtplib.SMTP(settings['smtp'], settings['smtp_port'])
            
            if st is None:
                print(f"Connected to {settings['smtp']}")
            else:
                st.write(f"Connected to {settings['smtp']}")
                
            server.starttls()
            server.login(from_email, password)
            
            text = msg.as_string()
            server.sendmail(from_email, to_email, text)
            server.quit()
            
            if st is None:
                print("Email sent successfully!")
            else:
                st.write("Email sent successfully!")
                
        except Exception as e:
            raise Exception(f'Failed to send email: {str(e)}. Please check your email/password and SMTP settings.')

    finally:
        # Clean up credentials from memory
        del password

def read_email(subject="Encrypted email", encryption_option='qkd_sim', **kwargs):
    st = kwargs.get('st', None)
    user = kwargs.get('email', None)
    
    if user is None:
        user = input("Enter your email: ")
        
    password = kwargs.get('password', None)
    if password is None:
        password = pwinput(prompt="Enter your password: ", mask='*')

    # Get email settings
    settings = get_email_settings(user)
    
    try:
        if st is not None:
            st.write('Logging into email...')
            
        mail = imaplib.IMAP4_SSL(settings['imap'])
        mail.login(user, password)
        
        # Rest of your existing read_email function...
        mail.select("inbox")
        
        if st is not None:
            st.write(f'Search for email with subject : {subject}')
            
        status, messages = mail.search(None, f'(SUBJECT "{subject}")')
        
        if status != "OK":
            print(f"No Emails found with subject: {subject}")
            if st is not None:
                st.write(f"No Emails found with subject: {subject} !")
            return None

        message_ids = messages[0].split()
        if st is not None:
            st.write(f"Emails found with subject: {len(message_ids)} !")
            st.write(f"Retrieving last email ...")

        for msg_id in message_ids:
            status, data = mail.fetch(msg_id, "(RFC822)")
            raw_email = data[0][1].decode()
            email_message = email.message_from_string(raw_email)

            for part in email_message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                if "attachment" not in content_disposition:
                    if content_type == "text/html":
                        html_body = part.get_payload(decode=True).decode()
                        soup = BeautifulSoup(html_body, "html.parser")
                        
                        if 'qkd' in encryption_option:
                            cypher_text_hex = soup.find('div', class_='cypher-text').get_text(strip=True)
                            key_id = soup.find('p', class_="key-id").get_text(strip=True).replace("Key ID:", "")
                            return {'cypher_hex': cypher_text_hex, 'key_id': key_id}
                            
                        elif 'pqc' in encryption_option:
                            encrypted_message = soup.find('div', class_='cypher-text').get_text(strip=True)
                            meta_data_div = soup.find('div', class_='meta-data')
                            cyphertext_paragraph = meta_data_div.find('p')
                            cyphertext = cyphertext_paragraph.text.replace('Cyphertext:', '').strip()
                            iv_paragraph = cyphertext_paragraph.find_next_sibling('p')
                            iv = iv_paragraph.text.replace('IV:', '').strip()
                            algo_type = soup.find('p', class_='algo-type').get_text(strip=True).replace("Algorithm:", "").strip()
                            return {
                                'encrypted_message': encrypted_message,
                                'cyphertext': cyphertext,
                                'iv': iv,
                                'algo': algo_type
                            }
                        else:
                            raise Exception(f"Option {encryption_option} not implemented.")
                            
    except Exception as e:
        raise Exception(f'Failed to read email: {str(e)}. Please check your email/password and IMAP settings.')
