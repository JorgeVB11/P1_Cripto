from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

"""ESTE ARCHIVO EQUIVALE A UN SOFTWARE INSTALADO EN EL ORDENADOR DEL USUARIO, INDEPENDIENTE DE NUESTRA APLICACIÓN.
DE FORMA OFICIAL NO SOMOS RESPONSABLES DEL MISMO"""


def main():
    """Función para firmar digitalmente un archivo"""
    mensaje = input("Path del mensaje a firmar: \n")
    key = input("Path de tu private key: \n")
    result = input("Path de la carpeta donde quieres guardar la firma: \n")
    result += "/" + "firma.pem"
    sign_digitally(mensaje, key, result)
    print("Mensaje firmado con éxito.\n")


def sign_digitally(mensaje_path, private_key_path, result_path):
    """Función para firmar digitalmente un mensaje"""
    # Abrimos la clave privada
    private_key = get_pkey(private_key_path)
    if private_key == -1:
        print("Private key no encontrada. Saliendo...\n")
        return -1
    # Abrimos el mensaje
    mensaje = get_message(mensaje_path)
    if mensaje == -1:
        print("Mensaje no encontrado. Saliendo...\n")
        return -1
    # Firmamos el mensaje
    sign = private_key.sign(
        mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Escribimos el mensaje en un .pem
    print(result_path)
    with open(result_path, "wb") as file:
        file.write(sign)


def get_pkey(path: str):
    """Función para devolver una pkey conenida en un .pem dado su address"""
    try:
        with open(path, 'rb') as pkey_file:
            private_key = serialization.load_pem_private_key(
                pkey_file.read(),
                password=None,
                backend=default_backend())
            return private_key
    except FileNotFoundError:
        print(f"El archivo {path} no fue encontrado.\n")
        return -1
    except IOError:
        print("Error al leer el archivo.\n")
        return -1
    except ValueError:
        print("Error al cargar la clave privada, puede que esté corrupta o mal formateada.\n")
        return -1
    except Exception as e:
        print(f"Un error inesperado ocurrió: {e}\n")
        return -1


def get_message(path: str):
    try:
        with open(path, "rb") as file:
            return file.read()
    except FileNotFoundError:
        print(f"El path es inválido.\n")
        return -1
    except IOError:
        print("Error al escribir el archivo.\n")
        return -1


# Ejecutamos el main
main()