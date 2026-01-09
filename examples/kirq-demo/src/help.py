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