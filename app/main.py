from menu import Menu

menu = Menu()
program_open = True


while program_open:
    if menu.type == 'inicial':
        if menu.menu_inicial() == 'r':
            if menu.register() == -1:
                continue
        elif menu.login() == -1:
            continue

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


"""

TODO: -meter comprobaciones en telf, contraseña al registrar
      -meter criptografia
      - hay un bug al cambiar contraseña y no meter una web que haya guardada
      - he guardado y salido y el json no se ha actualizado
"""
