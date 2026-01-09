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


