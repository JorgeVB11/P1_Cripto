from json_manager import JsonManager
import getpass


class Menu:
    def __init__(self):
        self._db = JsonManager("db.json")
        self._db.load_json()
        self.type = 'inicial'  # inicial/principal

    def menu_inicial(self):
        """"Método para registrarse o iniciar sesión"""
        eleccion = input("Bienvenido. ¿Quieres Registrarte (R) o iniciar Sesión (S)?: \n")
        while eleccion.lower() not in ['r', 's']:
            eleccion = input("Por favor, teclea 'R' para registrarte, 'S' para iniciar sesión o 'C' para cerrar: \n")
        return eleccion

    def menu_principal(self):
        """Método para elegir un servicio"""
        eleccion = input("¿Deseas ver una contraseña (1), verlas toda las webs registradas (2), añadir una contraseña "
                         "(3), cambiar una contraseña (4), eliminar una contraseña (5) o  guardar y salir (6)?\n")
        int(eleccion)
        while eleccion not in [1, 2, 3, 4, 5, 6]:
            eleccion = input("Por favor, teclea un comando válido")

    def register(self):
        """Registrar nuevo usuario"""
        usuario = input("¿Cuál es tu telf?: \n")
        if self._db.find_user(usuario):
            print("Este usuario ya existe, volviendo al menú anterior\n")
            return -1

        password = input("¿Cuál es tu contraseña?: \n")
        self._db.add_account(usuario, password)
        self.type = 'principal'
        return 0

    def login(self):
        """Inicio de sesion"""
        usuario = input("¿Cuál es tu telf?: \n")
        if not self._db.find_user(usuario):
            print("Usuario no encontrado. Volviendo al menú anterior...\n")
            return -1

        intentos = 3
        while intentos > 0:
            password = getpass.getpass("¿Cuál es tu contraseña?: \n")
            if not self._db.check_password(password):
                intentos -= 1
                print("Contraseña incorrecta. Tienes", intentos, " intentos\n")
            else:
                print("Contraseña correcta, iniciando sesion...\n")
                self.type = 'principal'
                return 0
        print("Volviendo al menú anterior...\n")
        return -1

    def show_password(self):
        """Método para mostrar la contraseña de una web"""
        web = input("Introduzca la web:\n")
        password = self._db.password_query(web)
        if not password:
            print("No tienes una contraseña para esta web. Volviendo al menú principal...\n")
            return -1
        print(password)
        return 0

    def show_webs(self):
        """Método para mostrar las webs para las que el usuario tiene contraseña"""
        webs = self._db.all_passwords()
        if not webs:
            print("Ninguna web registrada. Volviendo al menú anterior...\n")
            return -1
        print(webs)
        return 0

    def add_password(self):
        """Método para añadir una contraseña"""
        web = input("Introduzca la web:\n")
        password = input("Introduzca la contraseña:\n")
        if self._db.add_password(web, password) == 0:
            print("Contraseña añadida correctamente.\n")
            return 0
        print("Web no registrada. Volviendo al menú anterior...\n")
        return -1

    def change_password(self):
        """Método para cambiar una contraseña"""
        web = input("Introduzca la web:\n")
        password = input("Introduzca la nueva contraseña:\n")
        result = self._db.change_password(web, password)
        if result == -1:
            print("Web no registrada. Volviendo al menu anterior...\n")
            return -1
        if result == -2:
            print("Error cambiando la web. Volviendo al menu anterior...\n")
            return -2
        print("Contraseña cambiada correctamente.\n")
        return 0

    def remove_password(self):
        """Método para eliminar una contraseña"""
        web = input("Introduzca la web:\n")
        result = self._db.rmv_password(web)
        if result == -1:
            print("La web no está registrada. Volviendo al menú anterior...\n")
            return -1
        return 0

    def exit_sesion(self):
        """Método para volver al menú de inicio y guardar los cambios"""
        self.type = 'inicial'
        self._db.load_json()
        return 0