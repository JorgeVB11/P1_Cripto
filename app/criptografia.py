import argon2
import base64
import random
from OpenSSL import crypto, SSL
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES


""" TODO: -funcion crear certificado. -> devuelve el certificado al user para que pueda iniciar sesion con el       
        - funcion para validar el certificado para poder iniciar sesion
        - Los certificados ya estan firmados digitalmente, nos estamos quitando dos pajaros de un tiro
        - Guardamos en nuestra base de datos los certificados y la clave orivada, los dos encriptados (lo que podemos 
        hacer es pedir la contraseña primero, con ella derivamos la clave, y usamos esa clave para desencriptar el 
        certificado y la clave)
        - Al crear el certificado, le pedimos al user su nombre completo para poder meterlo dentro, y usamos su número 
        de teléfono como id unico que necesitamos para crear el certificado
        -Tengo que mirar bien lo de autofirmar el certificado para ser nosotros la entidad que emite certificados:
        lo he mirado y tenemos quqe generar nuestro certificado y firmarlo con la propia clave privada con la qu e la 
        creas. esa clave privada es la que vamos a usar para firmar los certificados que creemos, asi que podriamos 
        guardar nuestro certificado como un archivo en la app, y acceder a el cuando usemos certificados. PROBLEMA: hay 
        que cifrarlo, podiamos meterlo en un json aparte y cifrarlo de alguna forma
    
"""

class Criptografia:
    """Funciones que sirven para manejar la encriptación y desencriptación"""
    def __init__(self):
        self._ph = argon2.PasswordHasher()
    # Dudas:
    # Qué vamos a usar de clave pública y qué de clave privada. Pq nosotros solo tenemos una clave no?
    # A su vez he visto en un ejercicio que el certificado pasa N, que creo que es lo que se usaba para hacer el modulo
    # en RSA
    # Pero nosotros no hacemos RSA y por tanto no tenemos N, simplemente omitimos eso o cómo hacemos?
    @staticmethod
    def sign_digitally(self, hashed_password, private_key):
        """Vamos a firmar digitalmente la contraseña que ha sido hasheada previamente y luego tb crear el certificado"""
        sign = private_key.sign(hashed_password.encode(), padding.PSS(padding.MGF1(hashes.SHA256()),
                                                                      padding.PSS.MAX_LENGTH), hashes.SHA256())
        return sign

    @staticmethod
    def verify_sign(self, hashed_password, sign, public_key, certificate):
        """Método para verificar la firma y comprobar el certificado"""
        try:
            public_key.verify(sign, hashed_password.encode(), padding.PSS(padding.MGF1(hashes.SHA256()),
                                                                          padding.PSS.MAX_LENGTH), hashes.SHA256())
            # mi_certificado = self.check_certificate(certificate, sign)
            # Verificar certificado a continuacion
            return True
        except InvalidSignature:
            return False
    def create_certificate(self, user, userkey):
        private_key = crypto.PKey()
        private_key.generate_key(crypto.TYPE_RSA, 2048)

        # Crear un certificado autofirmado
        certificate = crypto.X509()
        certificate.get_subject().C = "ES"
        certificate.get_subject().ST = "Comunidad de Madrid"
        certificate.get_subject().L = "Pinto"
        certificate.get_subject().O = "Mi organización"
        certificate.get_subject().OU = "Mi unidad organizativa"
        certificate.get_subject().CN = "localhost"
        certificate.set_serial_number(1000)
        certificate.gmtime_adj_notBefore(0)
        certificate.gmtime_adj_notAfter(315360000)
        certificate.set_issuer(certificate.get_subject())
        certificate.set_pubkey(private_key)
        certificate.sign(private_key, 'sha256')
        # No estoy seguro si debo devolver la private_key o si esto hace que la deje desprotegida, lo hago para poder
        # sacar la publica a partir de ella pq no llego a estar seguro si se puede usar, ya que he visto que primero
        # se genera la privada y a partir de ella la publica, pero parece que al reves se raya.
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(userkey)
        )
        with open("private_key.pem", "wb") as f:
            #Guardamos clave privada
            f.write(pem)
        return certificate

    def check_certificate(self, certificate, sign):
        # segun veo los certificados están compuestos por {(clave publica, N), Firma}
        # Por tanto habría que verificar que recibimos eso
        pass

    def hash_password(self, password):
        """Método para hashear la contraseña"""
        hashed_pasword = self._ph.hash(password)
        print("Contraseña hasheada. Resultado: ", hashed_pasword)
        return hashed_pasword

    def compare_hash(self, password, hashed_password):
        """Método para comparar una contraseña con su versión hasheada"""
        try:
            self._ph.verify(hashed_password, password)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False

    @staticmethod
    def derive_password(password, salt):
        """Método para derivar la contraseña para conseguir una key"""
        derived_key = argon2.low_level.hash_secret(password.encode(), salt, time_cost=1, memory_cost=8, parallelism=1,
                                                   hash_len=128, type=argon2.low_level.Type.D)
        # Ahora obtenemos solo los bytes que conforman la clave (derived key es una cadena codificada que incluye más
        # elementos)
        derived_bytes_base64 = derived_key.split(b'$')[4]
        padding_clave = b'=' * (4 - (len(derived_bytes_base64) % 4))
        key = base64.urlsafe_b64decode(derived_bytes_base64 + padding_clave)
        print("Contraseña derivada. Key creada: ", key, "\n")
        return key

    @staticmethod
    def encrypt(datos_sin_codificar, key):
        """Método para encriptar"""
        # Pasamos los datos a bits
        datos = datos_sin_codificar.encode()
        cipher = AES.new(key, AES.MODE_EAX)
        # Aquí encritpamos y generamos la etiqueta de autenticación de datos
        ciphertext, tag = cipher.encrypt_and_digest(datos)
        # Necesitaremos el nonce para desencriptar
        nonce = cipher.nonce
        print("Datos encriptados. Ciphertext: ", ciphertext, " Tag: ", tag, " Nonce: ", nonce, "\n")
        return ciphertext, tag, nonce

    @staticmethod
    def desencrypt(key, ciphertext, tag, nonce):
        """Método para desencriptar"""
        try:
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            return data.decode()
        except ValueError:
            # Tampering detectado (data no coincide con tag, brecha de seguridad)
            return -1