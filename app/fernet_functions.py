from cryptography.fernet import Fernet


class FernetFunctions:
    """Funciones que sirven para encriptar y desencriptar"""
    def encriptar(self, word):
        """Encripto"""
        key = Fernet.generate_key()
        f = Fernet(key)
        token = f.encrypt(word)
        return key, token

    def desencriptar(self, key, token):
        """Desencripto"""
        f = Fernet(key)
        message = f.decrypt(token)
        return message