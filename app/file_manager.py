from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class FileManager:
    """Clase para manejar operaciones con archivos"""
    @staticmethod
    def get_certificate(path: str):
        """Función para devolver un certificado .pem dado su address"""
        try:
            with open(path, "rb") as ca_cert_file:
                pem_file = ca_cert_file.read()
                return x509.load_pem_x509_certificate(pem_file, default_backend())
        except FileNotFoundError:
            print(f"El archivo {path} no fue encontrado.\n")
        except IOError:
            print("Error al leer el archivo.\n")
        except ValueError:
            print("Error al cargar la clave privada, puede que esté corrupta o mal formateada.\n")
        except Exception as e:
            print(f"Un error inesperado ocurrió: {e}\n")

    @staticmethod
    def get_sign(path: str):
        try:
            with open(path, "rb") as sign_file:
                return sign_file.read()
        except FileNotFoundError:
            print(f"El archivo {path} no fue encontrado.\n")
            return False
        except IOError:
            print("Error al leer el archivo.\n")
            return False
        except Exception as e:
            print(f"Un error inesperado ocurrió: {e}\n")
            return False

    @staticmethod
    def write_pkey(private_key_path, private_key, password):
        try:
            with open(private_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.BestAvailableEncryption(password),
                ))
                return True
        except FileNotFoundError:
            print("El path es inválido.\n")
            return False
        except IOError:
            print("Error al escribir el archivo.\n")
            return False

    @staticmethod
    def write_message(path_archivo, mensaje):
        try:
            with open(path_archivo, "wb") as file:
                file.write(mensaje)
                return True
        except FileNotFoundError:
            print(f"El path es inválido.\n")
            return False
        except IOError:
            print("Error al escribir el archivo.\n")
            return False