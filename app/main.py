"""Main"""
from menu import Menu
from time import sleep
menu = Menu()
program_open = True
conseguido = False

while program_open:
    if menu.type == 'inicial':
        while not conseguido:
            operacion = menu.menu_inicial()
            if operacion == 'r':
                if menu.register() == 0:
                    conseguido = True
                    sleep(0.5)
                    continue
            elif operacion == 's':
                if menu.login() == 0:
                    conseguido = True
                    sleep(0.5)
                    continue
            else:
                conseguido = True
                program_open = menu.exit_system()
    sleep(1.5)
    if program_open:
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
                conseguido = menu.exit_sesion()
        print("\n")

# TODO: -hacer que el json se actualice cada vez que inicies sesion
#       -hacer que al descargar el json se comprueben todas las etiquetas para ver si hay brecha de seguridad
#       -meter firma digital y pki/certificao -> para comprobar la identidad del que modifica contraseñas.