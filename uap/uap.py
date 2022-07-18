from datetime import timedelta
from flask import Flask, json, request, render_template, session, redirect, url_for
from werkzeug.datastructures import cache_property
from database import CredentialsDatabase
import webbrowser
import os
import requests
import sys
import secrets
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding as aspadding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import Tuple
from itertools import repeat

app = Flask(__name__)

app.secret_key = secrets.token_hex(64)

# Number of challenges in the E-CHAP protocol. The default is 20, which grants a random success rate of around 9.5e-5%.
ECHAP_N = int(os.environ.get('ECHAP_N', '20'))


@app.get('/auth_request')
def auth_request():
    if 'service' not in request.args:
        return "INTERNAL ERROR: no service has been specified in the request."
    if 'reg_endpoint' not in request.args:
        return "INTERNAL ERROR: no register endpoint has been specified in the request."

    service = request.args.get('service')
    reg_endpoint = request.args.get('reg_endpoint')

    # Could be another browser window (webbrowser.open_new) or a completely different interface, but we open a tab on the default browser for simplicity
    webbrowser.open_new_tab('http://localhost:{port}/auth?service={service}&reg_endpoint={reg_endpoint}'.format(
        port=os.environ['FLASK_RUN_PORT'],
        service=service,
        reg_endpoint=reg_endpoint
    ))

    return "SUCCESS: authentication started"

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    db = CredentialsDatabase()

    if 'service' not in request.args:
        return "INTERNAL ERROR: the service name hasn't been transported correctly (is the app being navigated correctly?)."
    if 'reg_endpoint' not in request.args:
        return "INTERNAL ERROR: the register endpoint hasn't been transported correctly (is the app being navigated correctly?)."

    service = request.args.get('service')
    reg_endpoint = request.args.get('reg_endpoint')

    if request.method == 'POST':
        if request.form['type'] == 'login':
            master_password = request.form['master_password']
            if db.verify_master_password(master_password):
                session['master_password'] = master_password
                session.permanent = True
                app.permanent_session_lifetime = timedelta(minutes=3)
                accounts = db.get_credentials_by_service(service,master_password)
                return render_template('service-accounts.html',accounts=accounts,service=service, reg_endpoint=reg_endpoint, echap_N=ECHAP_N)
            else:
                return render_template('login.html', has_master_password=db.has_master_password(), error="Master password incorrect")

        elif request.form['type'] == 'register_master_password':
            master_password = request.form['master_password']
            if len(master_password) == 0:
                return render_template('login.html', error="Master password field must be filled out")
            else:
                session['master_password'] = master_password
                db.create_database_file('data', master_password)
                session.permanent = True
                app.permanent_session_lifetime = timedelta(minutes=3)
                accounts = []
                return render_template('service-accounts.html', accounts=accounts, service=service, reg_endpoint=reg_endpoint, echap_N=ECHAP_N)

        elif request.form['type'] == 'register':
            # In case the session cookie expired or is deleted
            if 'master_password' not in session:
                return render_template('login.html', has_master_password=db.has_master_password(), error='Login expired (re-login with the master password, and do the registration again).')

            username = request.form['username']
            password = request.form['password']

            master_password = session['master_password']

            if not db.verify_master_password(master_password):
                return "INTERNAL ERROR: wrong master password (have the cookies been tampered with?)."

            accounts = db.get_credentials_by_service(service,master_password)

            if username == "" or password == "":
                return render_template('service-accounts.html',accounts=accounts, service=service, reg_endpoint=reg_endpoint, echap_N=ECHAP_N, error='Both fields must be field out')

            for account in accounts:
                if account['username'] == username:
                    return render_template('service-accounts.html',accounts=accounts, service=service, reg_endpoint=reg_endpoint, echap_N=ECHAP_N, error='An account with that username already exists in the database.')

            # Securely encrypt the message so that only the service (should) decrypt it.
            # This already happens with HTTPS and the use of certificates, but we emulate it anyways.
            r = requests.get(url='http://' + service + '/pubkey')
            pubkey_bytes = r.content

            pubkey = load_pem_public_key(pubkey_bytes)

            register_data = json.dumps({
                'username': username,
                'password': password
            })
            
            encrypted_register_data = pubkey.encrypt(
                register_data.encode(encoding='utf-8'),
                aspadding.OAEP(
                    mgf=aspadding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            r = requests.post(
                url='http://' + service + reg_endpoint,
                data=encrypted_register_data
            )

            data = r.json()

            if 'status' not in data:
                return render_template('service-accounts.html',accounts=accounts, service=service, reg_endpoint=reg_endpoint, echap_N=ECHAP_N, error='The registration failed without status code.')
            if data['status'] != 0:
                if 'errorMsg' not in data:
                    return render_template('service-accounts.html',accounts=accounts, service=service, reg_endpoint=reg_endpoint, echap_N=ECHAP_N, error='The registration failed witm status code \'' + str(data['status']) + '\' and no message.')
                return render_template('service-accounts.html',accounts=accounts, service=service, reg_endpoint=reg_endpoint, echap_N=ECHAP_N, error='The registration failed with status code \'' + str(data['status']) + '\' and message \'' + data['errorMsg'] + '\'.')

            db.add_credentials(service,username,password,master_password)
            accounts.append({
                'username': username,
                'password': password
            })

            return render_template('service-accounts.html',accounts=accounts, service=service, reg_endpoint=reg_endpoint, echap_N=ECHAP_N)

        else:
            return f"INTERNAL ERROR: invalid POST type ('{request.form['type']}')."

    error = request.args['error'] if 'error' in request.args else None
    return render_template('login.html', has_master_password=db.has_master_password(), error=error)

@app.get('/echap_auth')
def echap_auth():

    db = CredentialsDatabase()

    if not 'service' in request.args:
        return 'INTERNAL ERROR: did not provide service'
    service = request.args['service']

    if not 'username' in request.args:
        return 'INTERNAL ERROR: did not provide username'
    username = request.args['username']

    if not 'reg_endpoint' in request.args:
        return 'INTERNAL ERROR: did not provide register endpoint (is the app being navigated correctly?)'
    reg_endpoint = request.args['reg_endpoint']

    error = 'Login expired (re-login with the master password, and do the registration again).'
    if 'master_password' in session:
        accounts = db.get_credentials_by_service(service, session['master_password'])
        for account in accounts:
            if account['username'] == username:
                status, login_endpoint = echap(service, username, account['password'], ECHAP_N)
                session.pop('master_password', None)
                if status==1:
                    error = f"E-CHAP ERROR [{status}] (second stage): session token received from the service is the same as the account's username." 
                elif status==2:
                    error = f"E-CHAP ERROR [{status}] (fourth stage): we failed authentication (our password did not match with the service's)."
                elif status==3:
                    error = f"E-CHAP ERROR [{status}] (fourth stage): service failed authentication (their password did not match with ours)."
                elif status==-1:
                    error = f"E-CHAP SEVICE DISAGREEMENT [{status}] (second stage): an account with this username '{username}' doesn't exist on the service side."
                elif status==-2:
                    error = f"E-CHAP SEVICE DISAGREEMENT [{status}] (second stage): the service did not agree with our KDF parameters (salt)."
                elif status==-3:
                    error = f"E-CHAP SEVICE DISAGREEMENT [{status}] (second stage): the service did not agree with our KDF parameters (number of iterations)."
                elif status==-4:
                    error = f"E-CHAP SEVICE DISAGREEMENT [{status}] (second stage): the service did not agree with the provided Initialization Vector for the Cipher CBC block mode."
                elif status==-5:
                    error = f"E-CHAP SEVICE DISAGREEMENT [{status}] (second stage): the service did not agree with the E-CHAP number of iterations."
                elif status!=0:
                    error = f"E-CHAP ERROR [{status}]: unknown error happened (the status code is unknown/undocumented)."
                else:
                    # Consume the login token and finish the login process
                    return redirect( 'http://' + service + login_endpoint )

    return redirect( url_for('auth', **{
        'service': service,
        'reg_endpoint': reg_endpoint,
        'error': error
    }))


"""
Here's how this implementation of an enhanced challenge-response authentication protocol (E-CHAP) works:

UAP                                                                             Service
        ------start_request     username    salt    niter   iv------------->
        <-----start_response    token   error   hash    salt----------------
         __________________________________________________________________
        /                        Repeat N times                            \ 

        ------chre  token   encrypt(cha_UAP, password)  iv------------------>
        <-----chre  token   encrypt(cha_Serv, password) iv-------------------

...                             [respond to challenges]                         ...

        ------chre  token   encrypt(cha_Serv+1, password)   iv-------------->
        <-----chre  token   encrypt(cha_UAP+1, password)    iv---------------

...                             [verify challenges]                             ...

        \__________________________________________________________________/

        ------finish    token---------------------------------------------->
        <-----finish    token   encrypt(login_endpoint)     iv--------------

The order should be enforced!
(This implementation is done with HTTP requests and responses, which simplifies this requirement)

There are 4 types of messages, each of them being a JSON document:
- start_request = {
    stage: start_request,
    iv: <iv>,
    username: <username>,
    salt: <salt>,
    niter: <niter>,
    N: <N>
}
    The first message is sent by the UAP, requesting the beginning of an authentication session. It sends
    the username of the account to login to, and the salt and number of iterations used to derive a key
    from the account's password using a password based key derivation function (PBKDF2HMAC), which will
    be used to encrypt/decrypt the challenges and responses. All messages (except start_response) also
    include the initialization vector that is used for the CBC mode used in the cipher. The number of
    iterations for this E-CHAP authentication session is also supplied.

- start_response = {
    stage: start_response,
    session_token: <session_token>,
    error: <error>,
    hash: <hash>,
    salt: <salt>
}
    The response message to the authentication request. Contains the session token that should be used to
    identify every future message of the protocol. The error is 0 unless there was an error on the Service
    side that did not allow it to initiate the authentication attempt (for example, if the requested account
    doesn't exist). In that case, the session_token should be null. If the E-CHAP parameters weren't agreed
    with, then the Service should ideally document which parameters are acceptable.
    The Service could be the one to send the parameters it finds acceptable in the first place, but it
    ends up not making a difference, since the UAP, being an authenticating party as well, should have the
    right to agree or not to the parameters as well.
    The Service's stored password is actually its hash with a salt, so the Service sends the hash and salt
    used in the password, so that the UAP can apply them to it and obtain the value that is stored on the
    Service's side.

- chre = {
    stage: chre,
    iv: <iv>,
    session_token: <session_token>,
    chre: encrypt(<challenge_response>, password)
}
    The challenge-response messages, these may represent either a challenge or the response to one.
    The order of the messages has to be enforced, or else a response can't be reliably associated with a
    challenge. The advantage of this is that a response can't be distinguished from a challenge in a single
    message. The content of 'chre' should be encrypted with the password using the already described method.

- finish = {
    stage: finish,
    iv: <iv>,
    session_token: <session_token>,
    login_endpoint: encrypt(<login_endpoint>, password)
}
    The final messages of the protocol. The UAP sends a message where the login_endpoint value is null. If the
    authentication of the client performed by the Service is successful, then it sends this message but the
    login_endpoint will be populated with the encrypted value of the endpoint that the client will have to access
    to login, which includes a login token (a nonce) created by the Service so that the client may consume it by
    accessing the sent endpoint and finish the login process (explained below). Encrypting prevents eavesdropping 
    third-parties from consuming this token and logging in.

The token represents the session token that the UAP wants to authenticate to. This token is
generated by the server, so that it can identify to what session those messages belong to
(like an ID). For instance, the UAP tells the service that it wants to authenticate the user
ALICE, then the service generates a token that represents that authentication attempt, and
sends it to the UAP. The username of the account itself is not used because multiple authentications
to the same username may be possible. Therefore, the first message doesn't send the session token,
but the username that will be used to create it.

The content is encrypted using the password that both the UAP and the Service have stored. When
receiving the messages, they should be decrypted using the same password. Therefore, the password
is used as a symmetric cypher. The salt and number of iterations are used to derive a key from the
password using a password-based key derivation function (in this case PBKDF2HMAC). This key is used
to encrypt/decrypt. The salt, number of iterations and IV are decided by the UAP, but the server can
reject those values by sending a 'start_response' message with error 2.

The challenge is an encrypted random unsigned 128-bit long integer, and the solution is the last bit of the
encrypted result of that same integer incremented by 1. It is crucial that the UAP sends the response to the
challenge first, so that server responses to the challenge can't be abused.

If the UAP authentication fails, then the last message that the Service sends should have a null value for
the login_endpoint field.

If the authentication is successful, the service will populate 'login_endpoint' with the path that the UAP
will access in order to finally login into the service (doesn't include the service's address).
We aren't immediately redirected to this token because the service may still fail authentication.

The encoding is UTF-8 and the messages that the UAP sends are HTTP POST messages with 'application/json' content type.
The other parameters of the PBKDF2HMAC function are the same (algorithm: SHA-256; length: 32).
The Cipher algorithm is AES and the block mode is CBC.
The byte conversion of the challenge (int → byte) is little-endian.
"""

def echap(service: str, username: str, password: str, N: int) -> Tuple[int, str]:
    """
Start the E-CHAP protocol done between the UAP and the service.

When the user attempts to login to an account (after providing the master password and specifying the account) start the CHAP protocol.

Returns a tuple of 2 values, where the first is the status/error code and the second value is the login endpoint if the login was successful,
and None otherwise.

A status code of 0 represents success and any other code specifies the kind of error that ocurred. The status codes are:
- 0 - successful login
- 1 - SECOND STAGE - session token is the same as the username (not properly generated)
- 2 - FOURTH STAGE - we failed authentication
- 3 - FOURTH STAGE - service failed authentication

Error codes are errors that happened on the service side (this function returns the negative value of these codes).
These errors are returned by the 'start_response' message. The error codes that can be returned by the service are:
- 0 - no error happened, continue the protocol
- 1 - the account doesn't exist on the service side
- 2 - did not agree with the KDF parameter 'salt'
- 3 - did not agree with the KDF parameter 'niter'
- 4 - did not agree with the Cipher parameter 'iv'
- 5 - did not agree with the E-CHAP parameter 'N'
    """

    """
    PREPARATION (KDF and IV)
    """

    password_bytes = password.encode(encoding='utf-8')
    salt = os.urandom(16)
    niter = 390000
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=niter
    )

    # Used to create the Cipher object ahead
    iv = os.urandom(16)

    """
    FIRST STAGE (start_request)
    """

    r = requests.post(
        'http://' + service + '/echap',
        json={
            'stage': 'start_request',
            'iv': iv.hex(),
            'username': username,
            'salt': salt.hex(),
            'niter': niter,
            'N': N
        }
    )

    """
    SECOND STAGE (start_response)
    """

    # In case there were errors, throw an exception
    r.raise_for_status()

    data = r.json()
    error = data['error']

    if error:
        print('Error (2): service error with error ' + str(error) + '.', file=sys.stderr)
        return -error, None

    if username == data['session_token']:
        print('Error (2): session token is the same as the username (not properly generated).', file=sys.stderr)
        return 1, None

    session_token = data['session_token']

    # Obtain the value stored on the Service for the password
    password_bytes = (password + data['salt'] if data['salt'] else '').encode(encoding='utf-8')
    if data['hash'] == 'sha512':
        hash_func = hashes.Hash(hashes.SHA512())
        hash_func.update(password_bytes)
        password_bytes = hash_func.finalize()

    # Create the Cipher object
    key = kdf.derive(password_bytes)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    """
    THIRD STAGE (chre)
    """

    service_failed = False
    for _ in repeat(None, N):
        # We send our challenge
        our_challenge = secrets.randbits(128)
        iv = os.urandom(16)
        cipher.mode = modes.CBC(iv)
        our_challenge_encrypted = encrypt_value( our_challenge.to_bytes(16,'little'), cipher ).hex()
        r = requests.post(
            'http://' + service + '/echap',
            json={
                'stage': 'chre',
                'iv': iv.hex(),
                'session_token': session_token,
                'chre': our_challenge_encrypted
            }
        )

        # We get the Service's challenge
        data = r.json()

        iv = bytes.fromhex( data['iv'] )
        cipher.mode = modes.CBC(iv)

        service_challenge = int.from_bytes( decrypt_value( bytes.fromhex(data['chre']), cipher ), 'little' )

        # We send the Service's challenge answer
        service_challenge_answer = secrets.randbits(128) if service_failed else service_challenge + 1
        # Always encrypts even if the service failed, so that timing attacks are harder to perform
        iv = os.urandom(16)
        cipher.mode = modes.CBC(iv)
        service_challenge_answer_encrypted = echap_create_response( service_challenge_answer, cipher )
        r = requests.post(
            'http://' + service + '/echap',
            json={
                'stage': 'chre',
                'iv': iv.hex(),
                'session_token': session_token,
                'chre': service_challenge_answer_encrypted
            }
        )

        print("Service failed:", service_failed, "| We sent as answer:", service_challenge_answer_encrypted, " | The actual answer:", echap_create_response( service_challenge+1, cipher ) if service_challenge > -1 else None)

        # We get the Service's answer to our challenge
        data = r.json()

        our_challenge_answer = data['chre']

        iv = bytes.fromhex( data['iv'] )
        cipher.mode = modes.CBC(iv)
        service_failed = service_failed or echap_create_response( our_challenge+1, cipher ) != our_challenge_answer

    """
    FOURTH STAGE (finish)
    """

    r = requests.post(
        'http://' + service + '/echap',
        json={
            'stage': 'finish',
            'iv': None,
            'session_token': session_token,
            'login_endpoint': None
        }
    )

    data = r.json()

    if data['login_endpoint'] == None:
        print("Error (4): we failed authentication", file=sys.stderr)
        return 2, None
        
    if service_failed:
        print("Error (4): service failed authentication", file=sys.stderr)
        return 3, None

    iv = bytes.fromhex( data['iv'] )
    cipher.mode = modes.CBC(iv)
    login_endpoint = unpad_value( decrypt_value( bytes.fromhex(data['login_endpoint']), cipher ) ).decode(encoding='utf-8')

    return 0, login_endpoint


def echap_create_response(number: int, c: Cipher) -> str:
    """
From the random integer, create the response that is sent on the network,
which includes encryption and extraction of the last bit on E-CHAP.
    """
    return bin( encrypt_value( number.to_bytes(16,'little'), c )[0] )[-1]

def unpad_value(value: bytes) -> bytes:
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(value) + unpadder.finalize()

def encrypt_value(value: bytes, c: Cipher) -> bytes:
    encryptor = c.encryptor()
    return encryptor.update(value) + encryptor.finalize()

def decrypt_value(value: bytes, c: Cipher) -> bytes:
    decryptor = c.decryptor()
    return decryptor.update(value) + decryptor.finalize()