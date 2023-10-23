import argon2
from Crypto.Cipher import AES
from base64 import urlsafe_b64encode, urlsafe_b64decode


class Criptografia:
    """Funciones que sirven para manejar la encriptación y desencriptación"""
    def __init__(self):
        self._ph = argon2.PasswordHasher()

    def hash_password(self, password):
        # Método para hashear la contraseña
        hashed_pasword = self._ph.hash(password)
        return hashed_pasword

    def compare_hash(self, password, hashed_password):
        try:
            self._ph.verify(hashed_password, password)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False

    @staticmethod
    def derive_password(password, salt):
        # Método para derivar la contraseña para conseguir una key
        derived_key = argon2.using(salt=salt, digest_size=32).hash(password)
        # Ahora obtenemos solo los bytes que conforman la clave (derived key es una cadena codificada que incluye más
        # elementos)
        derived_bytes = urlsafe_b64decode(derived_key.split('$')[-1])
        return derived_bytes

    @staticmethod
    def encrypt(datos, key):
        # Método para encriptar, solo acepta datos en bytes (usar .encode())
        cipher = AES.new(key, AES.MODE_EAX)
        # Aquí encritpamos y generamos la etiqueta de autenticación de datos
        ciphertext, tag = cipher.encrypt_and_digest(datos)
        # Necesitaremos el nonce para desencriptar
        nonce = cipher.nonce
        return ciphertext, tag, nonce

    @staticmethod
    def desencrypt(key, ciphertext, tag, nonce):
        # Método para desencriptar, devuelve datos en bytes
        try:
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            return data
        except ValueError:
            # Tampering detectado (data no coincide con tag, brecha de seguridad)
            return -1

