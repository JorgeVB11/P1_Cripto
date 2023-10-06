from json_manager import JsonManager


db = JsonManager("db.json")
db.load_json()

db.find_user(111111111)
print(db.check_password("prueba"))
print(db.password_query("Google"))
db.add_account(333333333, "contraseña3")
db.add_password("tiktok", "tiktok_contraseña")
db.change_password("tiktok", "2")
db.save_data()
