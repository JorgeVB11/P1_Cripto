import os
import time
import argon2
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from OpenSSL import crypto
from Crypto.Cipher import AES
from file_manager import FileManager

ADDRESS_PKEY = os.path.join("..", "ca_info", "ca_key.pem")
ADDRESS_CA_CERTIFICATE = os.path.join("..", "ca_info", "ca_cert.pem")


class Criptografia:
    """Funciones que sirven para manejar todos los aspectos criptográficos de la aplicación"""

    def __init__(self):
        self._ph = argon2.PasswordHasher()
        self._message = ""
        self._ca_cert = FileManager.get_certificate(f"../Certificados/AC2/ac2cert.pem")

    def verify_certificate(self, usuario):
        
        # Abrimos el certificado
        cert_user = FileManager.get_certificate(f"../Certificados/Usuarios/{usuario}-cert.pem")
        if not cert_user:
            return -1
        # Comprobamos que somos nosotros los que han emitido este certificado
        if cert_user.get_issuer() != self._ca_cert.get_subject():
            print("El certificado no ha sido emitido por nosotros.\n")
            return -1
        # Comprobamos que el tiempo actual está dentro de la validez del certificado
        ahora = time.time()
        inicio_validez = time.strptime(cert_user.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
        fin_validez = time.strptime(cert_user.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        # Convertimos las fechas de inicio y fin de validez en segundos desde la época UNIX
        inicio_validez_segundos = int(time.mktime(inicio_validez))
        fin_validez_segundos = int(time.mktime(fin_validez))
        if inicio_validez_segundos > ahora:
            print("La fecha del certificado es inválida.\n")
            return -1
        if fin_validez_segundos < ahora:
            print("El certificado está caducado.\n")
            return -1
        print("El certificado es válido\n")
        return 0

    def verify_sign(self, sign_path, usuario):
        user_cert = FileManager.get_certificate(f"../Certificados/Usuarios/{usuario}-cert.pem")
        user_sign = FileManager.get_sign(sign_path)
        try:
            crypto.verify(user_cert, user_sign, self._message, "sha256")
            print("La firma es válida.\n")
            return True
        except crypto.Error:
            print(crypto.Error)
            print("La firma es inválida.\n")
            return False

    def generate_message(self, usuario: str, path: str):

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        nonce = os.urandom(16).hex()
        message = f"Usuario: {usuario}\nTimestamp: {timestamp}\nNonce: {nonce}"
        self._message = message.encode()
        path_archivo = path + "/sign_me.txt"
        return FileManager.write_message(path_archivo, self._message)

    @staticmethod
    def generate_certificate(phone_number):
        original_working_directory = os.getcwd()
        os.chdir("../Certificados/AC2/")
        with open("./serial", "rb") as file:
            file_data = file.read().decode("utf-8")

        print("LOS SIGUIENTES MENSAJES LLEGAN A LA TERMINAL DE LA ENTIDAD CERTIFICADORA 2, EN LA DEL USUARIO NO SE "
              "DEBERÍA VER EN UN CASO REAL.\n")
        password = input("Introduce la contraseña de la pkey:\n")

        os.system(f"openssl ca -in ./solicitudes/{phone_number}_csr.pem -notext -config ./openssl_AC2.cnf --passin "
                  f"pass:{password}")
        print(os.getcwd())
        os.system(f"move nuevoscerts\\{file_data[:-1]}.pem  ..\\Usuarios\\{phone_number}-cert.pem")
        print("VOLVEMOS A LA TERMINAL DEL USUARIO.\n")
        os.chdir(original_working_directory)

    @staticmethod
    def generate_csr(phone_number, private_key):
        """Función para generaar un certificate signing request"""
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "MADRID"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, phone_number),
            x509.NameAttribute(NameOID.COMMON_NAME, "gestorcontraseñas.es"),
        ])).sign(private_key, hashes.SHA256())
        with open(f"../Certificados/AC2/solicitudes/{phone_number}_csr.pem", "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

    def generate_private_key_and_public_key(self, private_key_dest_path, password, phone):
        """Función para generar las claves para poder generar  un certificado"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        password = bytes(password, encoding="utf-8")
        if not FileManager.write_pkey(private_key_dest_path, private_key, password):
            return -1
        self.generate_csr(phone, private_key)

        return 0

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
            print("Tampering detectado (data no coincide con tag, brecha de seguridad)")
            return -1
