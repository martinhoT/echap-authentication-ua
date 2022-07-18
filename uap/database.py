import json
import os
from os import path
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken


class CredentialsDatabase:
    '''Create an empty database file'''
    def create_database_file(self, filename, master_password):
        data_dict = {
            'services': {}
        }
        self.save_database(filename, data_dict, master_password)
    
    '''Save and encrypt json into a file'''
    def save_database(self, filename: str, data_dict: dict, master_password: str):
        '''
        To encrypt the json into a file we:
            1) Open the file to write bytes
            2) Dump the python dictionary into json
            3) Create a random salt
            4) Encrypt the json
            5) Append the salt to the json and write to the file
        '''
        with open(filename, 'wb') as f:
            data_json = json.dumps(data_dict)

            salt = os.urandom(16)
            encrypted_json = self.encrypt_data(
                data_json.encode(), master_password.encode(), salt
            )

            f.write(salt + encrypted_json)

    '''Load and decrypt json from a file'''
    def load_database(self, filename: str, master_password: str):
        '''
        To decrypt the json from the file we:
            1) Open the file to read bytes
            2) Take the salt from the first 16 bytes
            3) Take the rest of the encrypted json
            4) Decrypt the json
            5) Load the json into a python dictionary
        '''
        with open(filename, 'rb') as f:
            salt = f.read(16)
            encrypted_json = f.read()

            if encrypted_json:
                data_json = self.decrypt_data(
                    encrypted_json, master_password.encode(), salt
                )
                data_dict = json.loads(data_json.decode())

                return data_dict

    '''Return true if a master password has already been registered'''
    def has_master_password(self):
        return path.exists('data')

    '''Return true if the correct master password was given as input'''
    def verify_master_password(self, master_password: str):
        try:
            self.load_database('data', master_password)
            return True
        except InvalidToken:
            return False

    '''Add new credentials to the database'''
    def add_credentials(
        self, service: str, username: str, password: str, master_password: str
    ):
        '''
        To add new credentials we:
            1) Create a new dictionary with the input credentials
            2) Load the database from a file into the dictionary
            3) Check what needs to be added to the database and add it
            4) Save the dictionary to a file
        '''
        credentials_dict = {'username': username, 'password': password}
        data_dict = self.load_database('data', master_password)

        if data_dict.get('services') == None:
            data_dict['services'] = {service: [credentials_dict]}
        elif data_dict.get('services').get(service) == None:
            data_dict['services'][service] = [credentials_dict]
        else:
            data_dict['services'][service].append(credentials_dict)

        self.save_database('data', data_dict, master_password)

    '''Get credentials from specific service from database'''
    def get_credentials_by_service(self, service: str, master_password: str):
        '''
        To get the credentials from a service we:
            1) Load the database into a python dictionary
            2) If the database is empty return []
            3) If the database has no services registered return []
            4) If the services don't have the specific service registered return []
            5) Return the credentials found for that service
        '''
        data_dict = self.load_database('data', master_password)
        if data_dict == None:
            return []
        
        services = data_dict.get('services')
        if services == None:
            return []
        
        service_credentials = services.get(service)
        if service_credentials == None:
            return []
        
        return service_credentials

    '''Create a urlsafe_b64encode based on the master password'''
    def derive_key(self, master_password: bytes, salt: bytes):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000
        )
        derive_key = kdf.derive(master_password)
        return base64.urlsafe_b64encode(derive_key)

    '''Return encrypted data using master password'''
    def encrypt_data(self, data: bytes, master_password: bytes, salt: bytes):
        key = self.derive_key(master_password, salt)
        return Fernet(key).encrypt(data)

    '''Return decrypted data using master password'''
    def decrypt_data(self, data: bytes, master_password: bytes, salt: bytes):
        key = self.derive_key(master_password, salt)
        return Fernet(key).decrypt(data)
