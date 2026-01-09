import marimo

__generated_with = "0.10.17"
app = marimo.App(width="medium")


@app.cell
def _():
    import marimo as mo
    return (mo,)


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        r"""
        # Kirq tutorial : ETSI014 protocol

        Welcome to this tutorial on the ETSI014 protocol. Here, you will learn how to interface with Quantum Key Distribution (QKD) systems, by using the standard ETSI014 API. 

        ## Basis

        To understand how this protocol works, we need to know a few things about QKD in general. Let's have a look at the schematic below :
        """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.image(".\images\qkd_etsi014.png")
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        r"""
        We have Alice, who generates and sends qubits, received and measured by Bob. The protocol used to generate keys from these qubits exchange varies, among them, we find the famous [BB84](https://medium.com/quantum-untangled/quantum-key-distribution-and-bb84-protocol-6f03cc6263c5), or the proprietary [COW](https://www.researchgate.net/publication/252509606_Coherent_one-way_quantum_key_distribution), and others. 

        In any case, most if not all QKD constructors propose the ESTI014 interface to allow users to retrieve keys. On the one hand, we have a user on Alice's side, who wants to exchange information with another user on Bob's side. 

        This key establishment process leads to the creation of a symmetrical key, present in both Bob and Alice's key delivery interface. Generally, the keys are stored in this way : 

        ```{key_ID=14ff4s-4546d-4213, key=dsrdj56s4fassff46aga4g6a7e5d65f4fa5are=}```

        Each key is identified with a unique `key_id` attribute, wich will be used to access the key. In practice, Alice will provide a key and it's corresponding ID, and the latter will be sent over the classical telecommunication channel to Bob so that he knows which key has been used by Alice.
        """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        r"""
        ## The API

        The ETSI014 protocol is a web API, accessible through any web browser. There exist three essential functions in the ETSI014 API :

        - `status`: to obtain information relative to the client that is probed.
        - `enc_keys`: accessed through Alice, which returns the encryption key and it's associated `key_id`.
        - `dec_keys`: accessed through Bob, which returns the decryption key, given the `key_id`.

        In Linux, one can access this interface using the `curl` web browsing command, in python we can also install the package `request`, that is equivalent. Now let's see the structure of the links in full detail, to check the status of Alice and Bob : 

        - Alice `enc_keys` : https://KMSA_IP/api/v1/keys/BOBSEA/enc_keys
        - Bob `dec_keys`: https://KMSB_IP/api/v1/keys/ALICESEA/dec_keys

        Now let's define our parameters : 

        - `KMSA_IP` and `KMSB_IP`: are the IP addresses of the Key Management System of Alice and Bob. These addresses have been configured by the QKD owner and will depend on the network configuration in which the QKD systems are embedded (subnetwork, gateway, mask, DNS). 
        - `BOBSAE` and `BOBSAE`: are the SEA identifiers of Alice and Bob, defined at the configuration of the QKD systems. This should be provided by the QKD owner.

        In a Nutshell, the first URL demands an encryption key from Alice interface `KMSA_IP`, in connection to Bob, identified as `BOBSEA`, while the second URL asks a decryption key from Bob interface `KMSB_IP` in connection to Alice, identified as `ALICESEA`.
        """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        """
        ## Time to play

        Now let's play with the API already, we are going to provide you with a list of information, and you will have to construct the correct links to provide to request, here is the table of data regarding the IDQ Cerberis XGR system

        | Interface | Module | IP | SAE |
        | ---- | ---- | ---- | ---| 
        | KMS | Alice | 192.168.101.202 | ETSIA |
        | KMS | Bob | 192.168.101.207 | ETSIB |
        """
    )
    return


@app.cell
def _():
    # Exercise 1 : fill in the missing information to construct the proper links to access the web API
    KMSA_IP = "192.168.101.202"
    KMSB_IP = "192.168.101.207"
    ALICESEA = "ETSIA"
    BOBSEA = "ETSIB"
    url_enc_key = f"https://{KMSA_IP}/api/v1/keys/{BOBSEA}/enc_keys"
    url_dec_key = f"https://{KMSB_IP}/api/v1/keys/{ALICESEA}/dec_keys"

    print(url_enc_key)
    print(url_dec_key)
    return ALICESEA, BOBSEA, KMSA_IP, KMSB_IP, url_dec_key, url_enc_key


@app.cell
def _(url_enc_key):
    import requests

    # You will get an error, it's normal go to the next block !
    response = requests.get(url_enc_key)
    print(response.text)
    return requests, response


@app.cell
def _():
    import subprocess

    def run_shell_command(command):
        try:
            # Run 'dir' command through the shell
            result = subprocess.run(command, capture_output=True, text=True, shell=True, check=True, encoding="cp850")
            # You might need to adapt the encoding ('utf-8', 'cp1252', ...)
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            print("Failed to run command:", e)
        except Exception as e:
            print("An error occurred:", e)
    return run_shell_command, subprocess


@app.cell
def _(KMSA_IP, run_shell_command):
    """
    The previous block doesn't work, let's try to debug this !

    Your first reflex should be to check if you have access to the IP adresses provided, if you don't, it's obviously problematic...

    1. To be able to access these adresses, you should first asks a user VPN access to Kirq's technical team, and set-up your machine using the provided VPN clients.

    2. If you have access to the VPN client and you are connected to it, let's now try to ping both Alice and Bob`s KMS interface using the command `ping` and the function run_shell_command() defined above.
    """

    # Exercice 2 : complete the following command, by proving the proper variable, in order to ping Alice and Bob's KMS interface :
    command_alice = f"ping {KMSA_IP}"
    run_shell_command(command_alice)

    # command_bob = f"ping {}"
    # run_shell_command(command_bob)
    return (command_alice,)


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        r"""
        ## Certificates

        However, even if you have direct access to the IPs addresses, the IRL above would not work, as you would need some parameters to make them functional, namely, the trusted certificates. Indeed, these QKD services are highly secure, and in other words, only trusted entities can access its features. 

        Below, we show an example of certificates that are currently deployed in one QKD system available in Kirq testbed, namely, the IDQ Cerberis XGR models. These certificates are located in `certificate/IDQ`, inside this same repository. Observe in detail the certificates and try to familiarize yourself with the nomenclature, it is pretty straightforward.
        """
    )
    return


@app.cell
def _(run_shell_command):
    # The command below should work on Windows, if you are running on Linux, uncomment the appropriate line and comment the other.

    run_shell_command("dir certificates\\IDQ\\")  # For Windows
    # run_shell_command("ls certificates/IDQ/") # For Linux
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        """
        ### Roles of Certificates in ETSI GS QKD 014:
        - **`Root CA` (Certificate Authority)** - `ChrisCA.pem`: Serves as the trusted issuer and manager of digital certificates, establishing a secure chain of trust for all entities in the network.
        - **`Client Key`**  - `ETSIA-key.pem` and `ETSIB-key.pem`: The private key of a client, used for decrypting received messages and signing outgoing messages, ensuring secure client authentication and communication integrity.
        - **`Client Certificate`** - `ETSIA.pem` and `ETSIB.pem`: A digital certificate that contains the client’s public key and identity, used to authenticate the client to other network entities and enable encrypted communications.

        In practice, all these certificates have been configured on our QKD system, and when providing them to the API, it will prove that you are a legitimate user. 

        Now that we have them, let's retry a `requests` command, by adding the proper argument into the function, and let's show the status of the system.
        """
    )
    return


@app.cell
def _(BOBSEA, KMSA_IP, __file__, requests):
    # Exercise 3 : provide the propper certificate to get status of Alice
    import os

    current_dir = os.path.dirname(os.path.abspath(__file__))
    path_certs = os.path.join(current_dir, 'certificates', 'IDQ')

    root_ca = os.path.join(path_certs, 'ChrisCA.pem')
    client_alice_cert = os.path.join(path_certs, 'ETSIA.pem')
    client_alice_key = os.path.join(path_certs, 'ETSIA-key.pem')

    url_status = f"https://{KMSA_IP}/api/v1/keys/{BOBSEA}/status"

    response_status = requests.get(
        url=url_status, verify=False, cert=(client_alice_cert, client_alice_key), timeout=10
    )
    print(response_status.text)

    '''
    Did you get an error of this sort ?

    raise ConnectTimeout(e, request=request)
    requests.exceptions.ConnectTimeout: HTTPSConnectionPool(host='192.168.101.202', port=443): Max retries exceeded with url: /api/v1/keys/ETSIB/status 

    You might not be connected to the VPN nor have access to the machine, double check and once connected, the error should be solved.

    '''
    return (
        client_alice_cert,
        client_alice_key,
        current_dir,
        os,
        path_certs,
        response_status,
        root_ca,
        url_status,
    )


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        r"""
        ## Clarifications

        Maybe you noticed that the code above does not use the `root_ca`, and that `verify=False`, the reason is because right now, 'ChrisCA.pem` is is a dummy certificate which is not secure, and we would need a trusted entity to verify the connexion. 

        ## Get keys

        Alright, it's time to get keys from Alice, using all the knowledge we acquired during this tutorial, now it's your turn provide the proper parameters and
        """
    )
    return


@app.cell
def _(client_alice_cert, client_alice_key, requests, url_enc_key):
    # Exercise 4 : provide the correct parameter to get a key

    cert = (client_alice_cert, client_alice_key)

    response_get = requests.get(
        url=url_enc_key, verify=False, cert=cert, timeout=10
    )
    data = response_get.text
    print(data)
    return cert, data, response_get


@app.cell
def _(data):
    # Extract data from the string

    import json

    def extract_key(data, type='full'):
        # Parse the JSON string into a Python dictionary
        json_data = json.loads(data)

        # Access the 'key' and 'key_ID' from the first item of the 'keys' list
        first_key_entry = json_data['keys'][0]

        if type == 'id':
            key_id = first_key_entry['key_ID']
            print("Key ID:", key_id)
            return key_id
        elif type == 'key':
            key_value = first_key_entry['key']
            print("Key:", key_value)
            return key_value
        else:
            key_value = first_key_entry['key']
            key_id = first_key_entry['key_ID']
            print("Key ID:", key_id)
            print("Key:", key_value)
            return key_value, key_id

    enc_key, key_id = extract_key(data)
    return enc_key, extract_key, json, key_id


@app.cell
def _(mo):
    mo.md(
        """
        # Decryption key

        Now that we received a key, pretend that you are on Bob's side, and received the `key_id`, using the proper URL and certificates. First let's look again at the certificates that we have in the folder :
        """
    )
    return


@app.cell
def _(run_shell_command):
    # The command below should work on Windows, if you are running on Linux, uncomment the appropriate line and comment the other.

    run_shell_command("dir certificates\\IDQ\\")  # For Windows
    # run_shell_command("ls certificates/IDQ/") # For Linux
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""Now fill in the following code to get keys from Bob. You should provide the proper URL and certificates, and provide the data as input""")
    return


@app.cell
def _(enc_key, extract_key, key_id, os, path_certs, requests, url_dec_key):
    # Exercise 5 : decryption key, fill in the missing information
    client_bob_cert = os.path.join(path_certs, 'ETSIB.pem')
    client_bob_key = os.path.join(path_certs, 'ETSIB-key.pem')

    cert_bob = (client_bob_cert, client_bob_key)

    data_key_id = {}
    data_key_id["key_IDs"] = [{"key_ID": key_id}]

    response_dec = requests.post(json=data_key_id,
                                 url=url_dec_key, verify=False, cert=cert_bob, timeout=10
                                 )
    data_dec = response_dec.text
    print(data_dec)

    dec_key = extract_key(data_dec, 'key')

    '''
    Validate that the dec_key is the same as the enc_key, they should be equal ! 
    '''

    print(dec_key == enc_key)

    '''
    Try to rerun the code a second time, you will get a NullKeyValue error. This is normal, the key has been consumed already, and has been deleted from the QKD pair!
    '''
    return (
        cert_bob,
        client_bob_cert,
        client_bob_key,
        data_dec,
        data_key_id,
        dec_key,
        response_dec,
    )


if __name__ == "__main__":
    app.run()
