from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization


class FileManager:
    """Clase para manejar operaciones con archivos"""
    @staticmethod
    def get_certificate(path: str):
        """Función para devolver un certificado .pem dado su address"""
        try:
            with open(path, "rb") as ca_cert_file:
                pem_file = ca_cert_file.read()
                return crypto.load_certificate(crypto.FILETYPE_PEM, pem_file)
        except FileNotFoundError:
            print(f"El archivo {path} no fue encontrado.\n")
        except IOError:
            print("Error al leer el archivo.\n")
        except ValueError:
            print("Error al cargar la clave privada, puede que esté corrupta o mal formateada.\n")
        except Exception as e:
            print(f"Un error inesperado ocurrió: {e}\n")

    @staticmethod
    def get_pkey(path: str):
        """Función para devolver una pkey conenida en un .pem dado su address"""
        try:
            with open(path, 'rb') as pkey_file:
                pkey_pem = pkey_file.read()
                return crypto.load_privatekey(crypto.FILETYPE_PEM, pkey_pem)
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
    def write_certificate(path, user_cert):
        try:
            with open(path, "wb") as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, user_cert))
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
