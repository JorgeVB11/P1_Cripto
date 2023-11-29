-----------------------------------
AUTORES:
-----------------------------------

Gabriel Ortega y Jorge Viñas, grupo 6

-----------------------------------
IMPORTANTE:
-----------------------------------

APP DESARROLLADA PARA SU USO EN WINDOWS (ejecutamos commandos para la terminal de windows)
En caso de no poder correrla en windows de ninguna manera, contactar con los autores para recibir una version adaptada
a linux

-----------------------------------
INSTRUCCIONES DE USO DE LA APP:
-----------------------------------

-Ejecutar el main
-Meter datos desde la consola
-Cuando pida direcciones meterlas en consola
-Cuando pida archvos meter la dirección completa y el nombre del archivo. Ejemplo:
    'C:\Users\Gabriel Ortega\Downloads\777777777-key.pem' -> Al meterlo a la terminal va sin comillas.
-El programa gestiona los certificados y los guarda, pero la clave privada del usuario se le devuelve encriptada con
una contraseña que se le pide.
-Una vez se haya comprobado la identidad del user, simplemente meter en terminal los comandos que se quieran emplear.

-----------------------------------
RESPECTO A LA TERMINAL DE AC2:
-----------------------------------

Cuando se genera un certificado, la terminal pasará de representar la del usuario a representar lo que le llegaría a la
de AC2, pues necesitamos una contraseña para desencriptar la clave privada de la CA para firmar los certificados.
Simplemente meter la contraseña 'cripto' sin las comillas y confirmar que se quiere firmar para poder continuar con el
proceso.

-----------------------------------
RESPECTO A FIRMAR DIGITALMENTE
-----------------------------------

El archivo firmado_digital representa un software instalado en el ordenador del usuario, nosotros no somos directamente
responsables de su desarrollo de forma oficial. De forma extraoficial, podemos aclarar que lo hemos creado para poder
firmar datos desde los archivos del proyecto para facilitar al profesor el uso de la app. Simplemente correrlo e irá
pidiendo los datos necesarios.