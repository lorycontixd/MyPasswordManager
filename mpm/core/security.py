import os
import re
import mpm_config
from cryptography.fernet import Fernet
from mpm_config import LOGGER

class Security:
    @staticmethod
    def generate_key():
        """
        Generates a key and save it into a file
        """
        key = Fernet.generate_key()
        with open(os.path.join(mpm_config.BASE_PATH, "secret.key"), "wb") as key_file:
            key_file.write(key)
        LOGGER.info(f"Generated new encryption key at secret.key")
        return key

    @staticmethod
    def load_key():
        """
        Load the previously generated key
        """
        LOGGER.info(f"Loaded existing encryption key from secret.key")
        return open(os.path.join(mpm_config.BASE_PATH, "secret.key"), "rb").read()
    
    @staticmethod
    def key_exists() -> bool:
        """
        Check if a key already exists
        """
        return os.access(os.path.join(mpm_config.BASE_PATH, "secret.key"), os.F_OK)
    
    @staticmethod
    def remove_key():
        file = os.path.join(mpm_config.BASE_PATH, "secret.key")
        if os.path.exists(file):
            os.remove(file)
            LOGGER.info(f"Existing encryption key has been deleted")
    
    @staticmethod
    def encrypt(source):
        """
        Encrypts a message
        """
        key = None
        key_exists = Security.key_exists()
        if not key_exists:
            raise ValueError(f"Trying to encrypt text but key does not exist")

        key = Security.load_key()

        encoded_message = source.encode("utf-8")
        f = Fernet(key)
        encrypted_message = f.encrypt(encoded_message)
        return encrypted_message

    @staticmethod
    def decrypt(encrypted_source):
        """
        Decrypts an encrypted message
        """
        key_exists = Security.key_exists()
        if not key_exists:
            raise ValueError(f"Trying to decrypt text but key does not exist")
        key = Security.load_key()
        f = Fernet(key)
        decrypted_message = f.decrypt(encrypted_source)

        return (decrypted_message.decode())

    @staticmethod
    def check_equal_encryption(encrypt1, encrypt2):
        decrypted1 = Security.decrypt(encrypt1)
        decrypted2 = Security.decrypt(encrypt2)
        return decrypted1 == decrypted2
    
    @staticmethod
    def password_security_check(password):
        """
        Verify the strength of 'password'
        Returns a dict indicating the wrong criteria
        A password is considered strong if:
            8 characters length or more
            1 digit or more
            1 symbol or more
            1 uppercase letter or more
            1 lowercase letter or more
        """

        # calculating the length
        length_error = len(password) < 8

        # searching for digits
        digit_error = re.search(r"\d", password) is None

        # searching for uppercase
        uppercase_error = re.search(r"[A-Z]", password) is None

        # searching for lowercase
        lowercase_error = re.search(r"[a-z]", password) is None

        # searching for symbols
        symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None

        # overall result
        password_ok = not ( length_error or digit_error or uppercase_error or lowercase_error or symbol_error )

        return {
            'password_ok' : password_ok,
            'length_error' : length_error,
            'digit_error' : digit_error,
            'uppercase_error' : uppercase_error,
            'lowercase_error' : lowercase_error,
            'symbol_error' : symbol_error,
        }
        