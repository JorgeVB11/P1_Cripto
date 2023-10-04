import sqlite3
import random


conexcion = sqlite3.connect("db")
cursor = conexcion.cursor()
cursor.execute("CREATE TABLE persona(nombre varchar(50)")