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