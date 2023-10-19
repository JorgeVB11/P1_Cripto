import re


class JsonManagerComprobacion:
    """Clase para hacer comprobaciones de los datos introducidos por el usuario"""

    @staticmethod
    def check_phonenum(phone):
        regex_phone_pattern = r'^([0-9]{9}$)$'
        if re.match(regex_phone_pattern, phone):
            return 0
        return -1

    @staticmethod
    def check_password(password):
        regex_password_pattern = r'^(?=(.*[a-z]))(?=(.*[A-Z]))(?=(.*[0-9]))(?=(.*[\W_])).{6,}$'
        if re.match(regex_password_pattern, password):
            return 0
        return -1
