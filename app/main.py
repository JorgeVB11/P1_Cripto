"""Main"""
from menu import Menu
from time import sleep
menu = Menu()
program_open = True


while program_open:
    if menu.type == 'inicial':
        if menu.menu_inicial() == 'r':
            while menu.register() == -1:
                sleep(0.5)
                continue
        else:
            while menu.login() == -1:
                sleep(0.5)
                continue
    sleep(1.5)

    eleccion = menu.menu_principal()
    match eleccion:
        case '1':
            menu.show_password()
        case '2':
            menu.show_webs()
        case '3':
            menu.add_password()
        case '4':
            menu.change_password()
        case '5':
            menu.remove_password()
        case '6':
            menu.exit_sesion()
    print("\n")
    sleep(1.5)

"""

TODO: 
    - Modificar base de datos para meter: 
        {
    "telf": "111111111",
    "password": "prueba", <- esto va hasheado
    "salt": "", <- salt para derivar la contraseña
    "data": {
      "Web": {
        "ciphertext": "contraseña cifrada",
        "tag": "tag para verificar datos",
        "nonce": "nonce para desencriptar"
      }
    }
  }
    
    -Modificar menu.py para adaptarse a la nueva base de datos y a la encriptacion (el json manager ya esta actualizado)
    - en el menu hay que codificar y decodificar, el json manager solo tiene de criptografia el comprobar que la c
    contraseña coincide con la hasheada, lo he adaptado a la nueva base de datos
"""
