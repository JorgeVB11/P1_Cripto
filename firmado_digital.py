from OpenSSL import crypto


def main():
    mensaje = input("Path del mensaje a firmar: \n")
    key = input("Path de tu private key: \n")
    result = input("Path de la carpeta donde quieres guardar la firma: \n")
    result += "/firma"
    sign_digitally(mensaje, key, result)


def sign_digitally(mensaje_path, private_key_path, result_path):
    """Función para firmar digitalmente un mensaje"""
    # Abrimos la clave privada
    private_key = get_pkey(private_key_path)
    # Abrimos el mensaje
    mensaje = get_message(mensaje_path)
    # Firmamos el mensaje
    sign = crypto.sign(private_key, mensaje, "sha256")
    # Escribimos el mensaje en un .pem
    path = result_path + "/firma.pem"
    with open(path, "wb") as file:
        file.write(sign)


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


def get_message(path: str):
    try:
        with open(path, "r") as file:
            return file.read()
    except FileNotFoundError:
        print(f"El path es inválido.\n")
        return False
    except IOError:
        print("Error al escribir el archivo.\n")
        return False


# Ejecutamos el main
main()