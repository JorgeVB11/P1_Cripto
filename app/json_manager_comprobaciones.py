import re


class JsonManagerComprobacion:
    """Clase para hacer comprobaciones de los datos introducidos por el usuario"""

    @staticmethod
    def check_phonenum(self, phone):
        regex_phone_pattern = r'^([0-9]{9}$)$'
        if re.match(regex_phone_pattern, phone):
            return phone

        phone = input("Debes registrarte mediante tu número de telefono.\n"
                      "Este debe ser de 9 digitos y compuesto por numeros únicamente")
        return -1

    @staticmethod
    def check_password(self, password):
        regex_password_pattern = r'^(?=(.*[a-z]))(?=(.*[A-Z]))(?=(.*[0-9]))(?=(.*[\W_])).{6,}$'

        if re.match(regex_password_pattern, password):
            return password

        password = input("La contraseña debe tener 6 caracteres y contener al menos:\n"
                         "1 letra minúscula, 1 mayúscula, 1 caracter especial y 1 numero\n")
        return -1
