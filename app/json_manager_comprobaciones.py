"""Documento en el que crearemos una clase para aquellas funciones del json que previamente deban pasar un filtro"""
import re
class JsonManagerComprobacion:
    def check_phonenum(self, phone):
        regex_phone_pattern = r'^([0-9]{9}$)$'
        if re.match(regex_phone_pattern,phone):
            return phone
        else:
            phone= input("Debes registrarte mediante tu número de telefono.\n"
                         "Este debe ser de 9 digitos y compuesto por numeros únicamente")
            return self.check_phonenum(phone)
    def check_password(self, password):
        regex_password_pattern = r'^(?=(.*[a-z]))(?=(.*[A-Z]))(?=(.*[0-9]))(?=(.*[\W_])).{6,}$'

        if re.match(regex_password_pattern, password):
            return password
        else:
            password = input("La contraseña debe tener 6 caracteres y contener al menos:\n"
                             " 1 letra minúscula, 1 mayúscula, 1 caracter especial y 1 numero")
            return self.check_password(password)