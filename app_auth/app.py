import re
import os
import secrets
import json

from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from werkzeug.utils import secure_filename
from database import ProductDatabase
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as aspadding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)

# Secret key used to sign the session cookies cryptographically
app.secret_key = b'`dqI0g/W>VN+HBo^?>(2'



# It just works
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2047
)

public_key = private_key.public_key()

login_tokens = {}
"""
Dictionary with the login tokens that are yet to be consumed.

Keys are the login tokens themselves and the values are the account username that they refer to.
"""

echap_session_tokens = {}
"""
Dictionary with the E-CHAP session tokens representing ongoing authentication sessions.

Keys are the session tokens themselves and the values are dictionaries like:
{
    username: <username of the account that is being authenticated>,
    waiting_for_challenge: <whether or not the server is waiting for the UAP's challenge; if false, then it's waiting for the UAP's response to our challenge>,
    our_challenge: <the last challenge that we created>,
    uap_challenge: <the last challenge that the UAP created>,
    uap_failed: <whether or not the UAP failed authentication during the protocol>,
    iterations: <a tuple with the number of iterations done so far and the max number that must be achieved>,
    cipher: <Fernet used in encrypting/decrypting the message content>
}

These values have to be saved so that we can know session data between different POST requests.
"""

ECHAP_MIN_SALT = 8
ECHAP_MIN_NITER = 300000
ECHAP_MIN_IV = 8
ECHAP_MIN_N = 20



UPLOAD_FOLDER = 'static/images/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/',  methods=['GET', 'POST'])
def shop():
    data = None
    if request.method == 'POST':
        
        search = re.sub(r"[^a-zA-Z0-9]+",' ',request.form['searchFor'])+"%"

        with ProductDatabase() as db:
            data = db.product_search(search)
    else:     
        with ProductDatabase() as db:
            data = db.product_get_all()
    return render_template('shop.html', data=data, uc=uc, logged_in=session.get('username') is not None)

@app.get('/pubkey')
def pubkey():
    return public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)

@app.route('/shop/<product>', methods=['GET', 'POST'])
def product(product=None):
    if request.method == 'POST':
        with ProductDatabase() as db:
            db.sale_add(session.get('username'), product, 1)
    session
    data = None
    with ProductDatabase() as db:
        data = db.product_get(product)

    return render_template('product.html', product=data, uc=uc, logged_in=session.get('username') is not None)

@app.post('/register')
def register():
    register_data_decrypted = private_key.decrypt(
        request.data,
        aspadding.OAEP(
            mgf=aspadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    register_data_dict = json.loads(register_data_decrypted)

    if 'username' not in register_data_dict:
        return jsonify({
            'status': 1,
            'errorMsg': 'Username field not specified.'
        })
    if 'password' not in register_data_dict:
        return jsonify({
            'status': 2,
            'errorMsg': 'Password field not specified.'
        })

    username = register_data_dict['username']
    password = register_data_dict['password']
    
    with ProductDatabase() as db:
        if db.user_exists(username):
            return jsonify({
                'status': 3,
                'errorMsg': 'An account with that username already exists.'
            })
        
        db.user_add(username, password)

    return jsonify({
        'status': 0,
        'errorMsg': None
    })

@app.get('/login')
def login():
    if 'token' not in request.args:
        return redirect('http://localhost:1919/auth_request?service={service}&reg_endpoint={reg_endpoint}'.format(
            service=os.environ['FLASK_RUN_HOST'] + ':' + os.environ['FLASK_RUN_PORT'],
            reg_endpoint='/register'
        ))
    
    token = request.args.get('token');
    
    if token not in login_tokens:
        return 'ERROR: Invalid login token.'
    
    # Successful login
    account_uname = login_tokens[token]
    session['username'] = account_uname
    with ProductDatabase() as db:
        session['role'] = db.user_role(account_uname)

    # Invalidate login token
    login_tokens.pop(token)

    return redirect(url_for('shop'))

@app.route('/cart')
def cart():
    data = None
    with ProductDatabase() as db:
        data = db.sale_get_product(session.get('username'))
    return render_template('cart.html', data=data, uc=uc, logged_in=session.get('username') is not None)

@app.route('/cart/remove')
def cart_remove():
    with ProductDatabase() as db:
        product = request.args.get('product', '')
        if product:
            db.sale_rem(session.get('username'), product)
        else:
            db.sale_rem_all(session.get('username'))
    return redirect(url_for('cart'))

@app.route('/add-product', methods=['GET', 'POST'])
def add_product():
    if request.method=='POST':
        if 'file' not in request.files:
            print("Fail")
        file = request.files['thumbnail']

        if file.filename == '':
            print("Fail")
            return redirect(request.url)
            
        filename = secure_filename(file.filename)
        file.save(UPLOAD_FOLDER+filename)
        file_path = '/' + UPLOAD_FOLDER+filename
        
        if '<' in request.form['name'] or '>' in request.form['name']:
            return render_template('add-product.html', uc=uc, logged_in=session.get('username') is not None, 
                                   error=True, error_msg='Product name can not contain the characters < or >')

        if '<' in request.form['description'] or '>' in request.form['description']:
            return render_template('add-product.html', uc=uc, logged_in=session.get('username') is not None, 
                                    error=True, error_msg='Product description can not contain the characters < or >')
        with ProductDatabase() as db:
            db.product_add(
                request.form['name'],
                request.form['price'],
                request.form['description'],
                file_path)

            return redirect(url_for('shop'))
    return render_template('add-product.html', uc=uc, logged_in=session.get('username') is not None, error=False)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('shop'))

# Route for handling E-CHAP authentication requests
# The details of the E-CHAP protocol implementation used are present in uap.py
@app.post('/echap')
def echap():
    data = request.json

    stage = data['stage']

    if stage == 'start_request':
        
        error = 0

        # Get the password from the database
        username = data['username']
        with ProductDatabase() as db:
            password = None
            password_salt = None
            if db.user_exists(username):
                password = db.user_pass(username)
                password_salt = db.user_salt(username)

        # Create a session token if the account was found
        session_token = secrets.token_hex(32) if password else None

        error = 1 if not error and not session_token else 0
        if not error:
            password_bytes = bytes.fromhex( password )
            print(password)
            salt = bytes.fromhex(data['salt'])
            niter = data['niter']
            iv = bytes.fromhex(data['iv'])
            echap_N = data['N']

            if not error:
                if len(salt) < ECHAP_MIN_SALT:
                    error = 2
                elif niter < ECHAP_MIN_NITER:
                    error = 3
                elif len(iv) < ECHAP_MIN_IV:
                    error = 4
                elif echap_N < ECHAP_MIN_N:
                    error = 5
                else:
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=niter
                    )
                    
                    key = kdf.derive(password_bytes)
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                    
                    echap_session_tokens[ session_token ] = {
                        'username': username,
                        'waiting_for_challenge': True,
                        'our_challenge': None,
                        'uap_challenge': None,
                        'uap_failed': False,
                        'iterations': (0, echap_N),
                        'cipher': cipher
                    }

        return jsonify({
            'stage': 'start_response',
            'session_token': session_token,
            'error': error,
            'hash': 'sha512',
            'salt': password_salt
        })

    # This is an ongoing authentication session
    session_token = data['session_token']
    echap_session = echap_session_tokens[ session_token ]

    username = echap_session['username']
    waiting_for_challenge = echap_session['waiting_for_challenge']
    our_challenge = echap_session['our_challenge']
    uap_challenge = echap_session['uap_challenge']
    uap_failed = echap_session['uap_failed']
    iterations = echap_session['iterations']
    cipher = echap_session['cipher']

    if stage == 'chre':

        chre = None
        iv = None

        # Incoming challenge from UAP for us to solve
        if waiting_for_challenge:
            iv = bytes.fromhex(data['iv'])
            cipher.mode = modes.CBC(iv)

            uap_challenge = int.from_bytes( decrypt_value( bytes.fromhex(data['chre']), cipher ), 'little' )

            our_challenge = secrets.randbits(128)
            iv = os.urandom(16)
            cipher.mode = modes.CBC(iv)
            our_challenge_encrypted = encrypt_value( our_challenge.to_bytes(16,'little'), cipher ).hex()

            chre = our_challenge_encrypted

        # Incoming response from UAP to our challenge
        else:
            our_challenge_answer = data['chre']

            iv = bytes.fromhex(data['iv'])
            cipher.mode = modes.CBC(iv)
            uap_failed = uap_failed or echap_create_response( our_challenge+1, cipher ) != our_challenge_answer

            uap_challenge_answer = secrets.randbits(128) if uap_failed else uap_challenge + 1
            iv = os.urandom(16)
            cipher.mode = modes.CBC(iv)
            uap_challenge_answer_encrypted = echap_create_response( uap_challenge_answer, cipher)

            chre = uap_challenge_answer_encrypted

            iterations = (iterations[0]+1, iterations[1])

        echap_session['waiting_for_challenge'] = not waiting_for_challenge
        echap_session['our_challenge'] = our_challenge
        echap_session['uap_challenge'] = uap_challenge
        echap_session['uap_failed'] = uap_failed
        echap_session['iterations'] = iterations

        return jsonify({
            'stage': 'chre',
            'iv': iv.hex(),
            'session_token': session_token,
            'chre': chre
        })
    
    if stage == 'finish':
        login_endpoint = None
        iv = None

        # Check if protocol has done the correct number of iterations and the UAP did not fail
        if iterations[0] == iterations[1] and not uap_failed:
            # Create a new login token
            new_login_token = secrets.token_urlsafe(256)
            login_tokens[ new_login_token ] = username
            iv = os.urandom(16)
            cipher.mode = modes.CBC(iv)
            login_endpoint = encrypt_value( pad_value(('/login?token=' + new_login_token).encode(encoding='utf-8')), cipher ).hex()

        # Terminate this E-CHAP authentication session
        echap_session_tokens.pop( session_token )
        
        return jsonify({
            'stage': 'finish',
            'iv': iv.hex() if iv else None,
            'session_token': session_token,
            'login_endpoint': login_endpoint
        })

    return None



# Reused from uap.py
def echap_create_response(number: int, c: Cipher) -> str:
    """
From the random integer, create the response that is sent on the network,
which includes encryption and extraction of the last bit on E-CHAP.
    """
    return bin( encrypt_value( number.to_bytes(16,'little'), c )[0] )[-1]

def pad_value(value: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(value) + padder.finalize()

def encrypt_value(value: bytes, c: Cipher) -> bytes:
    encryptor = c.encryptor()
    return encryptor.update(value) + encryptor.finalize()

def decrypt_value(value: bytes, c: Cipher) -> bytes:
    decryptor = c.decryptor()
    return decryptor.update(value) + decryptor.finalize()



# Utility functions for general use and better organization
# This is passed to the view (jinja templates), since it's purely cosmetic
class UtilityClass():

    def __init__(self):
        self.category = "Fruit"
        self.admin_identifier = "@"

    def normalize_product_name(self, name : str) -> str:
        return '{0} | {self.category}'.format(name.capitalize(), self=self)

    def normalize_user_username(self, username : str, role : str = 'regular') -> str:
        return '{0}{1}'.format(
                self.admin_identifier if role=='admin' else '',
                username.replace(self.admin_identifier, ''),
                self=self)

uc = UtilityClass()



if __name__ == '__main__':
    app.run()
    
