import argon2
import base64
from OpenSSL import crypto
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
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
        - funcion para pedir al user el path donde quieren guardar su certificado, y el nombre para el cert y clave
        (los archivos). La funcion deveria juntar los nombres para pasarselos al de crear el cert
    
"""


class Criptografia:
    """Funciones que sirven para manejar la encriptación y desencriptación"""
    def __init__(self):
        self._ph = argon2.PasswordHasher()

    @staticmethod
    def sign_digitally(hashed_password, private_key):

        sign = private_key.sign(hashed_password.encode(), padding.PSS(padding.MGF1(hashes.SHA256()),
                                                                      padding.PSS.MAX_LENGTH), hashes.SHA256())
        return sign

    @staticmethod
    def verify_sign(hashed_password, sign, public_key):

        try:
            public_key.verify(sign, hashed_password.encode(), padding.PSS(padding.MGF1(hashes.SHA256()),
                                                                          padding.PSS.MAX_LENGTH), hashes.SHA256())

            return True
        except InvalidSignature:
            return False

    @staticmethod
    def generate_certificate(self, id_telf, name, priv_key_path, certificate_path):
        # Generar una clave privada para el usuario
        user_key = crypto.PKey()
        user_key.generate_key(crypto.TYPE_RSA, 2048)
        # Crear un certificado para el usuario
        user_cert = crypto.X509()
        user_cert.set_version(2)  # Usamos la versión 3
        user_cert.set_serial_number(id_telf)
        user_cert.get_subject().CN = name
        user_cert.set_issuer()  # meter el issuer aqui
        user_cert.gmtime_adj_notBefore(0)
        user_cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # Validez de 1 año
        user_cert.set_pubkey(user_key)
        # Firmar el certificado del usuario con la clave privada de la CA
        nuestra_key = 0
        user_cert.sign(nuestra_key, 'sha256')  # meter nuestra key aqui
        # Exportar la clave privada y el certificado del usuario
        with open(priv_key_path, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, user_key))
        with open(certificate_path, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, user_cert))

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