import base64
import os
from criptografia import Criptografia
from json_manager import JsonManager
from json_manager_comprobaciones import JsonManagerComprobacion


class Menu:
    def __init__(self):
        self._cripto = Criptografia()
        self._db = JsonManager("db.json")
        self._db.load_json()
        self.type = 'inicial'  # inicial/principal
        self._key = ""

    @staticmethod
    def menu_inicial():
        """"Método para registrarse o iniciar sesión"""
        eleccion = input("Bienvenido. ¿Quieres Registrarte (R) o iniciar Sesión (S)?: \n")
        while eleccion.lower() not in ['r', 's']:
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
        # Guardamos la cuenta y hasheamos la contraseña
        self._db.add_account(usuario, self._cripto.hash_password(password), base64.b64encode(salt).decode('utf-8'))
        print("Usuario registrtado correctamente.\n")
        self.type = 'principal'
        return 0

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
            else:
                salt = base64.b64decode(self._db.get_salt())
                # Generamos la clave a partir de la contraseña
                self._key = self._cripto.derive_password(password, salt)
                print("Contraseña correcta, iniciando sesion...\n")
                self.type = 'principal'
                return 0
        print("Volviendo al menú anterior...\n")
        return -1

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
        if not ciphertext and not tag and not nonce:
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
        return 0