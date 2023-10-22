from menu import Menu
from time import sleep

menu = Menu()
program_open = True


while program_open:
    if menu.type == 'inicial':
        if menu.menu_inicial() == 'r':
            if menu.register() == -1:
                sleep(1.5)
                continue
        elif menu.login() == -1:
            sleep(1.5)
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
    -meter criptografia
    - hacer que al meter una contraseña no se vea el texto --> no se puede creo

REQUISITOS:
    -cifrado simétrico/asimetrico: al guardar contrasñas, hay que printear el resultado del cifrado, la longitud del
    cifrado y el algoritmo usado
    -Generación/verificación de etiquetas de autenticación de mensajes:  usar HMAC para garantizar que los datos no se 
    han alterado desde la última vez que se guardaron. Al guardar los datos, genera un HMAC y almacénalo junto con los 
    datos. Cada vez que cargues los datos, verifica el HMAC para asegurarte de que nadie ha modificado el archivo.
    -Generación/verificación de firma digital: permitir que los usuarios importen/exporten datos, firmar digitalmente 
    estos paquetes
    -Autenticación de las claves públicas mediante certificados (despliegue de PKI): importar un perfil, implementar un 
    sistema donde estos datos estén firmados con una clave privada y verificados con una clave pública
"""
