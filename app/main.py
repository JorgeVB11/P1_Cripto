from json_manager import JsonManager


db = JsonManager("db.json")
db.load_json()

"""db.find_user(111111111)
print(db.check_password("prueba"))
print(db.password_query("Google"))
db.add_account(333333333, "contraseña3")
db.add_password("tiktok", "tiktok_contraseña")
db.change_password("tiktok", "2")
db.save_data()"""


tipo_cuenta= input("Quieres Registrarte (R) o iniciar sesión (S): \n")
while tipo_cuenta.lower() != "r" and tipo_cuenta.lower()!= "s":
    tipo_cuenta= input("Por favor, teclea 'R' para registrarte o 'S' para iniciar sesión: \n")

usuario = input("¿Cuál es tu usuario?: \n")
password = input("¿Cuál es tu contraseña?: \n")
if tipo_cuenta.lower()=="s":
    while not db.find_user(usuario):
        usuario = input("Usuario no encontrado. ¿Cuál es tu usuario?: \n")
    intento_numero= 1
    while not db.check_password(password) and (intento_numero < 3):
        password = input("¿Cuál es tu contraseña?: \n")
        intento_numero += 1
    if intento_numero == 3:
        print("Demasiados intentos fallidos")
else:
    db.add_account(usuario, password)

continuar = True
while continuar==True:
    instruccion= input("Qué quieres hacer, ¿añadir o cambiar una contraseña?: \n")
    if instruccion.lower() == ("añadir" or "cambiar"):
        objetivo = input("La contraseña de qué página quieres guardar: \n")
        password_pag = input("Cual es la contraseña que quieres asignarle: \n")
        if instruccion.lower() == "cambiar":
            db.change_password(objetivo, password_pag)
        else:
            db.add_password(objetivo, password_pag)
        db.save_data()
    else:
        print("Instruccion incorrecta, selecciona otra:\n")
    continuar = input("¿Quieres continuar realizando operaciones (True/False?: \n")
print("Ejecución terminada")





















