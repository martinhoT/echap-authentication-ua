# Project 2 - Authentication (Team 36)

Implementation of an User Authentication Application (UAP) for various network services, using the website impletented in [Project 1](https://github.com/detiuaveiro/project-1---vulnerabilities-equipa_36) as an example.

In order to test the advantages of the E-CHAP protocol, a malicious version of the Service app (the website) has been developed, which will try to obtain responses to arbitrary challenges from the UAP, in hopes of extracting information about the secret key used to compute them. The malicious version is in `app_auth/app_attacker.py`, while the normal one is in `app_auth/app.py`.

Both the Service and the UAP were implemented in Python using Flask.

## Overview

Essentially, the steps taken during the authentication are:

1. Service sends an HTTP GET request to the UAP on the endpoint `/auth_request`, providing as parameters its DNS name and the Service's endpoint that will be used to register new accounts by the UAP;
2. The UAP opens a web browser (opens a tab if the process already exists) on the link `/auth`, which is the main interface;
3. In case the UAP's database is empty, provide a master password for the encryption/decryption of the credentials database. Otherwise, ask for the master password;
4. If the list of accounts for that Service is empty, immediately prompt for the registration of a new account (using the Service's registration endpoint), otherwise show the list of available accounts first;
5. Click on the 'Login' button on one of the accounts, which will send a GET request to the UAP's `/echap_auth` endpoint, including as parameters the Service's DNS name, the username of the chosen account and the Service's registration endpoint (this is purely to simplify redirection to `/auth` in case things go wrong). This starts the E-CHAP protocol between the UAP and the Service;
6. The Service sends to the UAP the endpoint that the client must go to in order to finish the login process;
7. The UAP redirects the client, logging them in.

## Pre-requisites

In order to run both applications, install the requirements present in the `requirements.txt` (ideally, a virtual environment should be created):
```
pip install -r requirements.txt
```

## API

### UAP API

- `/auth_request`
    
    - `GET` : open the UAP interface. It should receive the following parameters:
        
        - `service` : the DNS name of the Service
        - `reg_endpoint` : the registration endpoint that will be used by the UAP when registering new accounts
        
        These parameters are sent by the Service to the UAP through the `/login` route, which is visited when clicking on the 'Login' button in the website.

- `/auth`

    - `GET` : main application interface, presents the form used to login/register with the master password. It should only be accessed by the UAP itself. The parameters it receives are:
    
        - `service` : *same as above*
        - `reg_endpoint` : *same as above*
        - `error` : error message in case there was an error
    
    - `POST` : present the accounts for the Service after the master password has been provided in the form of the `GET` request (using the `POST` action).

- `/echap_auth`

    - `GET` : obtain the credentials for the provided `service` and `username` combination and initiate the E-CHAP authentication protocol. It should receive the following parameters:
    
        - `service` : *same as above*
        - `reg_endpoint` : *same as above*
        - `username` : username of the chosen account to login

### Service API

Below are shown the Service's API endpoints that are used for the E-CHAP authentication and registration of accounts:

- `/pubkey`

    - `GET` : provide the public key that should be used to encrypt registration messages, so that passwords aren't sent in the clear (mimicking the use of HTTPS/certificates);

- `/register`

    - `POST` : adds a new user to the Service. The data sent should be a JSON document like:
    
    ```json
    {
        "username": "<username>",
        "password": "<password>"
    }
    ```
    
    encrypted using the public key in `/pubkey`. It sends the following JSON response:

    ```json
    {
        "status": <status code>,
        "errorMsg": "<errorMsg>"
    }
    ```
    where `errorMsg` is the error message in case something goes wrong (for example, an account already exists with that username), and `status` is the error code in case there was an error or 0 otherwise.

- `/login`

    - `GET` : login into an account if a login token is specified (redirecting to the Service's main page on success), otherwise call the UAP to continue with the login process. It receives as parameters:
    
        - `token` : the login token that should be consumed by the user in order to actually login into the Service. If none is provided, then start the UAP. If an invalid token is provided, send an error message indicating such.

- `/echap`

    - `POST` : the endpoint that the UAP will use to communicate with the Service during the E-CHAP protocol. The full message flow for this route (what it receives, what it sends back) will be explained in the [E-CHAP](#e-chap) section.

## E-CHAP

Here's how this implementation of an enhanced challenge-response authentication protocol (E-CHAP) works (function `echap` on `uap/uap.py`):

| UAP | | Service |
|-----|-|---------|
||`-----start_request \| username \| salt \| niter \| iv-------->`||
||`<----start_response \| token \| error \| hash \| salt---------`||
||`____________________Repeat N times________________________`||
||`-----chre \| token \| encrypt(cha_UAP, password) \| iv------->`||
||`<----chre \| token \| encrypt(cha_Serv, password) \| iv-------`||
|`...`|`...............[respond to challenges]....................`|`...`|
||`-----chre \| token \| encrypt(cha_Serv+1, password) \| iv---->`||
||`<----chre \| token \| encrypt(cha_UAP+1, password) \| iv------`||
|`...`|`.................[verify challenges]......................`|`...`|
||`__________________________________________________________`||
||`-----finish \| token----------------------------------------->`||
||`<----finish \| token \| encrypt(login_endpoint) \| iv---------`||

*(A better formatted version of this diagram is present in `uap/uap.py`)*

The order should be enforced!
(This implementation is done with HTTP requests and responses, which simplifies this requirement)

There are 4 types of messages, each of them being a JSON document:
- **start_request**
```json
{
    "stage": "start_request",
    "iv": "<iv>",
    "username": "<username>",
    "salt": "<salt>",
    "niter": <niter>,
    "N": <N>
}
```
The first message is sent by the UAP, requesting the beginning of an authentication session. It sends
the username of the account to login to, and the salt and number of iterations used to derive a key
from the account's password using a password based key derivation function (`PBKDF2HMAC`), which will
be used to encrypt/decrypt the challenges and responses. All messages (except `start_response`) also
include the initialization vector that is used for the CBC mode used in the cipher. The number of
iterations for this E-CHAP authentication session is also supplied.

- **start_response**
```json
{
    "stage": "start_response",
    "session_token": "<session_token>",
    "error": <error>,
    "hash": "<hash>",
    "salt": "<salt>"
}
```
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

- **chre**
```json
{
    "stage": "chre",
    "iv": "<iv>",
    "session_token": "<session_token>",
    "chre": encrypt("<challenge_response>", password)
}
```
The challenge-response messages, these may represent either a challenge or the response to one.
The order of the messages has to be enforced, or else a response can't be reliably associated with a
challenge. The advantage of this is that a response can't be distinguished from a challenge in a single
message. The content of `chre` should be encrypted with the password using the already described method.

- **finish**
```json
{
    "stage": "finish",
    "iv": "<iv>",
    "session_token": "<session_token>",
    "login_endpoint": encrypt("<login_endpoint>", password)
}
```
The final messages of the protocol. The UAP sends a message where the login_endpoint value is null. If the
authentication of the client performed by the Service is successful, then it sends this message but the
login_endpoint will be populated with the encrypted value of the endpoint that the client will have to access
to login, which includes a login token (a nonce) created by the Service so that the client may consume it by
accessing the sent endpoint and finish the login process (explained below). Encrypting prevents eavesdropping 
third-parties from consuming this token and logging in.

### Details

The token represents the session token that the UAP wants to authenticate to. This token is
generated by the server, so that it can identify to what session those messages belong to
(like an ID). For instance, the UAP tells the service that it wants to authenticate the user
"ALICE", then the service generates a token that represents that authentication attempt, and
sends it to the UAP. The username of the account itself is not used because multiple authentications
to the same username may be possible. Therefore, the first message doesn't send the session token,
but the username that will be used to create it.

The content is encrypted using the password that both the UAP and the Service have stored. When
receiving the messages, they should be decrypted using the same password. Therefore, the password
is used as a symmetric cypher. The salt and number of iterations are used to derive a key from the
password using a password-based key derivation function (in this case `PBKDF2HMAC`). This key is used
to encrypt/decrypt. The salt, number of iterations and IV are decided by the UAP, but the server can
reject those values by sending a `start_response` message with error 2.

The challenge is an encrypted random unsigned 128-bit long integer, and the solution is the last bit of the encrypted result of that
same integer incremented by 1. It is crucial that the UAP sends the
response to the challenge first, so that server responses to the challenge can't be abused.

If the UAP authentication fails, then the last message that the Service sends should have a null value for
the login_endpoint field.

If the authentication is successful, the service will populate `login_endpoint` with the path that the UAP
will access in order to finally login into the service (doesn't include the service's address).
We aren't immediately redirected to this token because the service may still fail authentication.

### Other notes:

- The encoding is UTF-8 and the messages that the UAP sends are HTTP POST messages with `application/json` content type.
- The other parameters of the PBKDF2HMAC function are the same (algorithm: SHA-256; length: 32).
- The Cipher algorithm is AES and the block mode is CBC.
- The byte conversion of the challenge (`int` → `byte`) is little-endian.
- The default value chosen for N is 20, which seemed reasonable enough, providing a chance of random success of around 9.5e-5%. It seemed a reasonable tradeoff between ease of random success and minimum display of responses to challenges.

## UAP Database

The uap database consists of an encrypted file with data in the JSON format, containing the credentials of the user to his different services.

The JSON data has the following structure:
```json
{
    "services": {
        "service1": [
            {
                "username": "user1",
                "password": "pass1"
            },
            {
                "username": "user2",
                "password": "pass2"
            }
        ]
    }
}
```

This file is stored encrypted on disk, everytime it needs to be read or written to, the following occurs:
1. It's contents are loaded into a python string;
2. This python string is then decrypted using the application master password, obtaining the JSON data;
3. This data will then be loaded into a python dictionary using the json library; 
4. This dictionary can then be operated on. 

After all the desired operations are complete:
1. The dictionary is again transformed into JSON; 
2. It's encrypted using the master password 
3. It's stored into a file on disk.

Having this process in mind, the flux of the interactions between the database and the UAP go as follows:

1. User is using the UAP for the first time and so registers the master password which causes the database to create the database file writing the skeleton of the JSON data structure;

    ```json
    {
        "services": {}
    }
    ```

2. UAP gets the credentials to the service the user is on causing the database to open the encrypted file, load it's contents into a dictionary, get the list of credentials from the specified service and return them to the UAP;
3. User registers a new account to the service he is using which causes the database to load the encrypted file, add the new service if it doesn't exist and add the new credentials to that service, encrypt the new file and save it;
4. User is using the UAP for the second time and so doesn't have to register a master password but has to login with the previously created master password, to verify that the password doing the login is the registered password the database tries to decrypt the file using the login input password, if this operation is successful then the password is correct, otherwise the password is wrong.

## Attacker Service

As explained in the beginning, a malicious version of the application was done, mainly in order to test the workings of the UAP protocol.

As an example, below is the output of an authentication attempt from the UAP on a malicious Service instance.

### UAP

```
Service failed: False | We sent as answer: 1  | The actual answer: 1
Service failed: True | We sent as answer: 1  | The actual answer: 0
Service failed: True | We sent as answer: 0  | The actual answer: 0
Service failed: True | We sent as answer: 0  | The actual answer: 0
Service failed: True | We sent as answer: 0  | The actual answer: 1
Service failed: True | We sent as answer: 1  | The actual answer: 1
Service failed: True | We sent as answer: 0  | The actual answer: 0
Service failed: True | We sent as answer: 0  | The actual answer: 0
Service failed: True | We sent as answer: 0  | The actual answer: 1
Service failed: True | We sent as answer: 1  | The actual answer: 1
Service failed: True | We sent as answer: 1  | The actual answer: 1
Service failed: True | We sent as answer: 0  | The actual answer: 0
Service failed: True | We sent as answer: 0  | The actual answer: 0
Service failed: True | We sent as answer: 1  | The actual answer: 0
Service failed: True | We sent as answer: 0  | The actual answer: 1
Service failed: True | We sent as answer: 0  | The actual answer: 0
Service failed: True | We sent as answer: 0  | The actual answer: 0
Service failed: True | We sent as answer: 1  | The actual answer: 1
Service failed: True | We sent as answer: 1  | The actual answer: 1
Service failed: True | We sent as answer: 0  | The actual answer: 0
```

### Attacker

```
Challenge → Response list:
183408966336019770163726610949461575728 → 1
188184826559205244228830789303296613708 → 1
100851509166637349942140173396407846728 → 0
117614665230195527134935751377552023922 → 0
13424408829650940749852568835017429231 → 0
64054309453176735993294688197925539619 → 1
104103129374027835861911302622398185903 → 0
1462197501343561769700763924387567801 → 0
60368724971892233222194273060983592637 → 0
250025158510094845875819086544124113462 → 1
41858253873884352103671335361093001313 → 1
192249015999909085040428748207548542032 → 0
44889596990165270500544563364394178036 → 0
98526861742412762001838149186171875892 → 1
252308534562420331554737090333709638184 → 0
176902342757406393372039308319627957085 → 0
31515839218704793428168471296026125882 → 0
197591024783373852597125872951479633744 → 1
111566854922148060210988435837147099404 → 1
88473580000625842858626656817760149915 → 0
```

As it can be seen, after the attacker failed on the second attempt, it started receiving random responses afterwards, without knowing when it failed.

## Security and miscellaneous details

There are some decisions and features that were implemented with the intent of increasing the security of the authentication process:

- The CHAP algorithm naturally requires that both parties contain the same value used to compute responses to challenges. Therefore, the first version of this algorithm used plain text passwords, which required the Service to store those plain text passwords. We then kept the hashing + salting that was present in the previous project, which provides more secrecy on the actual password that was used to compute that value. Although, it doesn't prevent attackers from taking advantage of those hashed and salted values to authenticate to the Service anyway.

- The UAP may have errors during execution (either by running the E-CHAP algorithm or by other interactions, such as inputting the master password). Regarding the E-CHAP errors, there is only one type of errors that don't even initiate the challenge-response exchanges: errors from the Service (for example, an account with the provided username not existing, or disagreement with protocol parameters)

- The initialization vector is always sent when a value is encrypted, since this vector has to be always randomized on each encryption with the same key, or else it's much less secure.

- Since the challenge-response messages are always 128 bits long (which is an encrypted 128-bit integer with AES, block size 128), then padding is not used. Padding is only used when sending and receiving the `login_endpoint`, since the value of that field is variable. This prevents padding errors from happening during the challenge-response exchange when encryption/decryption is performed with different keys (and thus the padding will have an incorrect format/syntax).

- After the UAP/Service sees that the other party failed authentication, it doesn't simply send a random bit, instead they create a random number as a response, encrypt it and obtain the last bit. Therefore, since the actions performed will be similar between a normal and a failed authentication verification, timing attacks will be harder to perform (and so, it's harder to know when the authentication failed).

- Some errors in the UAP are not normal, and are usually due to improper navigation/usage. These are marked as `INTERNAL ERROR`s, and they are sent to the client as strings.

- Symmetric encryption/decryption of the database used Fernet (since it automatically detects whether or not some encrypted content can be correctly decrypted), while the symmetric encryption/decryption of the messages in E-CHAP used the Cipher class, in order to have more control over these processes (if Fernet was used instead, then a `chre` message encrypted with a different key couldn't be decrypted).

- The UAP keeps track of the current master password session using cookies managed by the `session` object from Flask. These cookies are automatically cleared when the authentication process finishes, and expire after some time.

## Authors

- [danyjf](https://github.com/danyjf)
- [martinhoT](https://github.com/martinhoT)
- [LazyProgramer](https://github.com/LazyProgramer)

## Sources
- CSS theme for the UAP adapted from: https://codepen.io/boudra/pen/YXzLBN
