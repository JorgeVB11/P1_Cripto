import json
from json_exception import JsonException


class JsonManager:
    def __init__(self, name):
        self._json_file_name = name
        self._current_user = ""
        self._data_list = []
        self._account = []

    def load_json(self):
        """This method loads the json file into the data list"""
        try:
            with open(self._json_file_name, "r", encoding="utf-8", newline="") as file:
                self._data_list = json.load(file)
        except FileNotFoundError:
            # file is not found , so  init my data_list
            self._data_list = []
        except json.JSONDecodeError as ex:
            raise JsonException("JSON Decode Error - Wrong JSON Format") from ex

    def save_data(self):
        """This method saves the data list into the json file"""
        try:
            with open(self._json_file_name, "w", encoding="utf-8", newline="") as file:
                json.dump(self._data_list, file, indent=2)
        except FileNotFoundError as ex:
            raise JsonException("Wrong file or file path") from ex
        return True

    def find_user(self, phone):
        """Función para encontrar a un usuario y devolver su contraseña"""
        for user in self._data_list:
            if phone == user["telf"]:
                self._current_user = phone
                self._account = user
                return True
        return False

    def check_password(self, password):
        """Método para comparar una contraseña con la de la cuenta del usuario"""
        if password == self._account["password"]:
            return True
        return False

    def password_query(self, web):
        """Método para devolver una contraseña guardada en la cuenta"""
        if web in self._account["data"]:
            return self._account["data"][web]
        return False

    def add_account(self, phone, password):
        """Añadir una cuenta al data_list"""
        new_account = {"telf": phone,
                       "password": password,
                       "data": {}}
        self._account = new_account
        self._current_user = phone
        self._data_list.append(new_account)

    def add_password(self, web, password):
        """Añadir una nueva contraseña a una cuenta"""
        for user in self._data_list:
            if user["telf"] == self._current_user:
                user["data"][web] = password
                return True
        return False

    def change_password(self, web, new_password):
        """Cambiar una contraseña"""
        for user in self._data_list:
            if user["telf"] == self._current_user:
                if web in user["data"]:
                    user["data"][web] = new_password
                    return True
                return -1  # Código de error si la web no esta registrada en las contraseñas del usuario
            return -2  # Código de error si el usuario no se encuentra