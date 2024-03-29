import base64
import os
from time import sleep
from criptografia import Criptografia
from json_manager import JsonManager
from json_manager_comprobaciones import JsonManagerComprobacion


class Menu:
    """Clase para configurar la interfaz de usuario y los requests que esta hace a funcionalidades técnicas"""
    def __init__(self):
        self._cripto = Criptografia()
        self._db = JsonManager("db.json")
        self._db.load_json()
        self.type = 'inicial'  # inicial/principal
        self._key = ""

    def menu_inicial(self):
        """"Método para registrarse o iniciar sesión"""
        eleccion = input("Bienvenido. ¿Quieres Registrarte (R), iniciar Sesión (S) o terminar Operaciones(T)?: \n")
        # Cargamos la base de datos para tenerla actualizada
        self._db.load_json()
        while eleccion.lower() not in ['r', 's', 't']:
            eleccion = input("Por favor, teclea 'R' para registrarte o 'S' para iniciar sesión:\n")
        return eleccion.lower()

    @staticmethod
    def menu_principal():
        """Método para elegir un servicio"""
        eleccion = input("¿Deseas ver una contraseña (1), ver toda las webs registradas (2), añadir una contraseña "
                         "(3), cambiar una contraseña (4), eliminar una contraseña (5) o  guardar y salir (6)?\n")
        int(eleccion)
        while eleccion not in ['1', '2', '3', '4', '5', '6']:
            eleccion = input("Por favor, teclea un comando válido\n")
        return eleccion

    def register(self):
        """Registrar nuevo usuario"""
        # Pedimos usuario
        usuario = input("¿Cuál es tu telf?: \n")
        while JsonManagerComprobacion.check_phonenum(usuario) == -1:
            usuario = input("Introduzca un número de teléfono válido (9 dígitos): \n")
        if self._db.find_user(usuario):
            print("Este usuario ya existe, volviendo al menú anterior\n")
            return -1
        # Pedimos contraseña
        password = input("¿Cuál es tu contraseña?: \n")
        while JsonManagerComprobacion.check_password(password) == -1:
            password = input("La contraseña debe tener al menos 6 caracteres y contener al menos:\n"
                             "1 letra minúscula, 1 mayúscula, 1 caracter especial y 1 numero\n")
        # Generamos salt
        salt = os.urandom(16)
        # Generamos la clave a partir de la contraseña
        self._key = self._cripto.derive_password(password, salt)
        # Creamos el certificado digital
        self.gestion_generacion_cert(usuario)
        # Guardamos la cuenta y hasheamos la contraseña
        self._db.add_account(usuario, self._cripto.hash_password(password), base64.b64encode(salt).decode('utf-8'))
        print("Usuario registrtado correctamente.\n")
        self.type = 'principal'
        return 0

    def gestion_generacion_cert(self, usuario):
        """Función para reunir toda la info necesaria para certificado y llamar a las funciones que lo crean"""
        print("Creando certificado digital...\n")
        cert_password = input("Introduce una contraseña para cifrar la  clave privada de tu certificado:\n")
        pkey_route = input("Escribe la ruta en la que quieres guardar tu clave\n")
        while not os.path.exists(pkey_route):
            pkey_route = input("Dirección invalida, introduce una válida\n")
        pkey_item_route = (pkey_route + "/" + usuario + "-key.pem")
        if self._cripto.generate_private_key_and_public_key(pkey_item_route, cert_password, usuario) == -1:
            print("Volviendo al menú anterior...\n")
            return -1
        self._cripto.generate_certificate(usuario)

    def login(self):
        """Inicio de sesion"""
        # Pedimos usuario
        usuario = input("¿Cuál es tu telf?: \n")
        if not self._db.find_user(usuario):
            print("Usuario no encontrado. Volviendo al menú anterior...\n")
            return -1
        # Pedimos contraseña
        intentos = 3
        while intentos > 0:
            password = input("¿Cuál es tu contraseña?:\n")
            if not self._db.check_password(password):
                intentos -= 1
                print("Contraseña incorrecta. Tienes", intentos, " intentos\n")
                continue
            # Conseguimos la salt para derivar la password
            salt = base64.b64decode(self._db.get_salt())
            # Generamos la clave a partir de la contraseña
            self._key = self._cripto.derive_password(password, salt)
            # Ahora comprobamos la identidad del usuario con su certificado
            if self.check_certificate(usuario) == -1:
                break
            print("Todo correcto, iniciando sesión...\n")
            self.type = 'principal'
            print("Comprobando si todas tus contraseñas están intactas...\n")
            for item in self._db.get_account()["data"]:  # Comprobamos que las contraseñas no han sido alteradas
                ciphertext, tag, nonce = self._db.password_query(item)
                if self._cripto.desencrypt(self._key, ciphertext.encode(), tag.encode(), nonce.encode()) == -1:
                    print("Te recomendamos cambiar las contraseñas que tenías en la base de datos, por si el atacante "
                          "tuviera tu contraseña de la cuenta\n")
                    return -1
            print("Todo correcto.\n")
            return 0
        print("Volviendo al menú anterior...\n")
        return -1

    def check_certificate(self, usuario):
        """Función para getsionar todos los aspectos de verificación de certificado"""
        if self._cripto.verify_certificate(usuario) == -1:
            # Si el certificado no es válido, creamos uno nuevo
            return -1
        print("Necesitamos que firmes un archivo de texto que vamos a generar.\n")
        message_path = input("Danos un path para guardar el .txt: \n")
        while not self._cripto.generate_message(usuario, message_path):
            message_path = input("Introduce otro path: \n")
        print("Cuando termines de firmar, dinos el path de tu archivo que contenga la firma.\n")
        sleep(1)
        sign_path = input("Danos el path de la firma: \n")
        while not self._cripto.verify_sign(sign_path, usuario):
            sign_path = input("Introduce de nuevo el path de la firma: \n")

    @staticmethod
    def exit_system():
        print("Operaciones terminadas")
        return False

    def show_password(self):
        """Método para mostrar la contraseña de una web"""
        webs = self._db.all_webs()
        if not webs:
            print("Ninguna web registrada. Volviendo al menú anterior...\n")
            return -1
        web = input("Introduzca la web:\n")
        # Conseguimos toda la info relacionada con la contraseña
        ciphertext, tag, nonce = self._db.password_query(web)
        # En caso de que la web no esté reguistrada con una contraseña
        if (ciphertext == -1) and (tag == -1) and (nonce == -1):
            print("No tienes una contraseña para esta web. Volviendo al menú principal...\n")
            return -1
        # Pasamos los parametros a la función de desencriptado en bytes
        password = self._cripto.desencrypt(self._key, base64.b64decode(ciphertext), base64.b64decode(tag),
                                           base64.b64decode(nonce))
        # Comprobamos is la contraseña es congruente con su tag
        if password == -1:
            print("ALERTA: BRECHA DE SEGURIDAD DETECTADA\n")
        print(password)
        return 0

    def show_webs(self):
        """Método para mostrar las webs para las que el usuario tiene contraseña"""
        webs = self._db.all_webs()
        if not webs:
            print("Ninguna web registrada. Volviendo al menú anterior...\n")
            return -1
        print(webs)
        return 0

    def add_password(self):
        """Método para añadir una contraseña"""
        web = input("Introduzca la web:\n")
        if self._db.password_query(web) != (-1, -1, -1):
            print("Esta web ya ha sido registrada. Volviendo al menú anterior...\n")
            return -1
        password = input("Introduzca la contraseña:\n")
        encrypted_password, tag, nonce = self._cripto.encrypt(password, self._key)

        if self._db.add_password(web, base64.b64encode(encrypted_password).decode('utf-8'),
                                 base64.b64encode(tag).decode('utf-8'), base64.b64encode(nonce).decode('utf-8')) == -1:
            print("Error guardando la contraseña. Volviendo al menú anterior...\n")
            return -2
        print("Contraseña añadida correctamente.\n")
        return 0

    def change_password(self):
        """Método para cambiar una contraseña"""
        # Comrobar si hay alguna web registrada
        webs = self._db.all_webs()
        if not webs:
            print("Ninguna web registrada. Volviendo al menú anterior...\n")
            return -1
        # Pedir la web
        web = input("Introduzca la web:\n")
        # Comprobar si la web está registrada
        if self._db.password_query(web) == (-1, -1, -1):
            print("Esta web no ha sido registrada. Volviendo al menú anterior...\n")
            return -2
        # Pedir la contnraseña y encriptarla
        password = input("Introduzca la nueva contraseña:\n")
        encrypted_password, tag, nonce = self._cripto.encrypt(password, self._key)
        if self._db.add_password(web, base64.b64encode(encrypted_password).decode('utf-8'),
                                 base64.b64encode(tag).decode('utf-8'), base64.b64encode(nonce).decode('utf-8')) == -1:
            print("Error cambiando la contraseña. Volviendo al menú anterior...\n")
            return -3
        print("Contraseña cambiada correctamente.\n")
        return 0

    def remove_password(self):
        """Método para eliminar una contraseña"""
        # Comrobar si hay alguna web registrada
        webs = self._db.all_webs()
        if not webs:
            print("Ninguna web registrada. Volviendo al menú anterior...\n")
            return -1
        web = input("Introduzca la web:\n")
        result = self._db.rmv_password(web)
        if result == -1:
            print("La web no está registrada. Volviendo al menú anterior...\n")
            return -1
        print("Se ha eliminado la web.\n")
        return 0

    def exit_sesion(self):
        """Método para volver al menú de inicio y guardar los cambios"""
        self.type = 'inicial'
        self._db.save_data()
        return False