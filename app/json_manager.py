import json
from json_exception import JsonException
from criptografia import Criptografia


class JsonManager:
    def __init__(self, name):
        self._json_file_name = name
        self._current_user = ""
        self._data_list = []
        self._account = {}
        # Objeto que ejecuta métodos criptográficos
        self._cripto = Criptografia()

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
        if self._cripto.compare_hash(password, self._account["password"]):
            return True
        return False

    def get_salt(self):
        """Método para conseguir el salt de una cuenta"""
        return self._account["salt"]

    def password_query(self, web):
        """Método para devolver una contraseña cifrada guardada en la cuenta"""
        if web in self._account["data"]:
            return self._account["data"][web]["ciphertext"], self._account["data"][web]["tag"], \
                   self._account["data"][web]["nonce"]
        return -1, -1, -1

    def add_account(self, phone, password, salt):
        """Añadir una cuenta al data_list"""
        new_account = {"telf": phone,
                       "password": password,
                       "salt": salt,
                       "data": {}}
        self._account = new_account
        self._current_user = phone
        self._data_list.append(new_account)

    def add_password(self, web, password, tag, nonce):
        """Añadir una nueva contraseña a una cuenta"""
        for user in self._data_list:
            if user["telf"] == self._current_user:
                user["data"][web] = {"ciphertext": password, "tag": tag, "nonce": nonce}
                return 0
        return -1

    def all_webs(self):
        """Método para devolver todas las webs registradas en un usuario"""
        return list(self._account["data"].keys())

    def rmv_password(self, web):
        """Método para eliminar una contraseña"""
        if web in self._account["data"]:
            del self._account["data"][web]
            return 0
        return -1