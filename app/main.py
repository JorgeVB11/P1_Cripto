from menu import Menu

menu = Menu()
program_open = True
menu_type = 'inicial'  # inicial/principal

while program_open:
    if menu_type == 'inicial':
        if menu.menu_inicial() == 'r':
            menu.register()
        else:
            login = menu.login()
            if login == -1:
                continue





"""if tipo_cuenta.lower()=="s":
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
"""




















