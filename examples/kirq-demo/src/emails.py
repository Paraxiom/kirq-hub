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
