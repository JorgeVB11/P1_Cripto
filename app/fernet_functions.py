from cryptography.fernet import Fernet


class FernetFunctions:
    """Funciones que sirven para manejar la encriptación y desencriptación"""

    @staticmethod
    def encriptar(self, word):
        """Encripto"""
        key = Fernet.generate_key()
        f = Fernet(key)
        token = f.encrypt(word)
        return key, token

    @staticmethod
    def desencriptar(self, key, token):
        """Desencripto"""
        f = Fernet(key)
        message = f.decrypt(token)
        return message

# deberiamos separar la funcion de encriptar en dos para que la otra devuelva la llave y sea mas facil guardarla?
# como guardamos la llave? hayq ue guardarla?