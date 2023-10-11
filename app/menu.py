from json_manager import JsonManager

class Menu:
    def __init__(self):
        self._db = JsonManager("db.json")
        self._db.load_json()


    def menu_inicial(self):
        """"Método para registrarse o iniciar sesión"""
        eleccion = input("Bienvenido. ¿Quieres Registrarte (R) o iniciar Sesión (S)?: \n")
        while eleccion.lower() != 'r' and 's':
            eleccion = input("Por favor, teclea 'R' para registrarte, 'S' para iniciar sesión o 'C' para cerrar: \n")
        return eleccion


    def register(self):
        """Registrar nuevo usuario"""
        usuario = input("¿Cuál es tu telf?: \n")
        password = input("¿Cuál es tu contraseña?: \n")

        self._db.add_account(usuario, password)

    def login(self):
        """Inicio de sesion"""
        usuario = input("¿Cuál es tu telf?: \n")
        if not self._db.find_user(usuario):
            print("Usuario no encontrado. Volviendo al menú anterior...\n")
            return -1

        password = input("¿Cuál es tu contraseña?: \n")
        intentos = 3
        while intentos > 0:
            if not self._db.check_password(password):
                intentos -= 1
                print("Contraseña incorrecta. Tienes", intentos, " intentos\n")
            else:
                print("Contraseña correcta, iniciando sesion...\n")
                return 0
        return -1




    def exit_sesion(self):
        self._db.load_json()