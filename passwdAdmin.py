# Author: Adrián Fernández Álvarez
# Version: 0.1.2

# Cryptography
from Cryptodome.Hash import MD5, SHA256
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import base64

#GUI
import tkinter as tk
from tkinter.filedialog import askopenfilename, asksaveasfilename
tk.Tk().withdraw()

#Others
from getpass import getpass
import os, shutil
import time, datetime, string, random
import sqlite3

#----------------------------------------------Encryption----------------------------------------------

#Funcion de creacion de un hash a partir de un texto
def hash(txt, mode='MD5', save=False):
    #Selector de modo de cifrado hash por defecto MD5
    if mode=='MD5':
        hash_obj = MD5.new()
    elif mode=='SHA256':
        hash_obj = SHA256.new()
    
    # Guardado del txt en un archivo temporal para poder convertirlo a bytes
    if type(txt)!=type(b'a'):
        with open('.cache/hash.tmp', 'w') as temp_file: 
            temp_file.write(txt)
            temp_file.close()
        with open('.cache/hash.tmp', 'rb') as temp_file: 
            data = temp_file.read()
            temp_file.close()
    else:
        data = txt

    #Cifrado con el modo seleccionado anteriormente y reescritura en el archivo
    hash_obj.update(data)
    #Selector de modo de guardado (si se guaradara el tmp o no)    
    if save:
        with open('.cache/hash.tmp', 'w') as temp_file: 
            temp_file.write(str(base64.b64encode(hash_obj.digest())))
            temp_file.close()
    else:
        try:
            os.remove('.cache/hash.tmp')
        except FileNotFoundError: pass
    return base64.b64encode(hash_obj.digest())

# Funcion para cifrar el texto
def cif_txt(texto):
    key = read_key('.cache/user.key')
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    txt_padded = pad(texto.encode('utf-8'), AES.block_size)
    txt_cif = cipher.encrypt(txt_padded)
    return base64.b64encode(iv + txt_cif).decode('utf-8')

# Función para descifrar el texto
def descif_txt(txt_cif):
    key = read_key('.cache/user.key')
    txt_cif = base64.b64decode(txt_cif)
    iv = txt_cif[:AES.block_size]
    txt_cif = txt_cif[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    txt_descif = unpad(cipher.decrypt(txt_cif), AES.block_size)
    return txt_descif.decode('utf-8')


#----------------------------------------------Others----------------------------------------------

# Función para generar y guardar la clave en un archivo
def generate_key():
    key_file = asksaveasfilename(defaultextension='key', title='Guardado de la key de encriptacion')
    key = get_random_bytes(32)
    with open(key_file, 'wb') as file:
        file.write(base64.b64encode(key))
    return key

#Funcion para leer la key de encriptacion
def read_key(path):
    with open(path, 'rb') as file:
        data = file.read()
        file.close()
    return base64.b64decode(data)

# Funcion que crea una contraseña aleatoria segun un largo dado que por defecto es 20 y la guarda en la base de datos si el usuario lo requiere
def random_passwd(long=20, save=False):
    caracters = [i for i in string.printable]
    passwd = ''
    for i in range(long):
        passwd+=random.choice(caracters[0:94])
    if save:
        os.system('cls')
        print(f' La contraseña generada es: {passwd}')
        with open('.cache/passwd_history', 'a') as file:
            file.write(passwd)
            file.write('\n\n')
            file.close()
        its_ok = input(' Deseas guardar la contraseña en tu base de datos? (y/n): ').lower()
        if its_ok == 'y' or its_ok == 's' or its_ok == 'yes' or its_ok == 'si':
            save_passwd(passwd=passwd)
            pass
        elif its_ok == 'n' or its_ok == 'no' or its_ok == 'nou' or its_ok == '':
            print(' Podras consultar el historial de contraseñas generadas')
        else: 
            print(' No has introducido una opción valida')
    return passwd



#----------------------------------------------DB----------------------------------------------

#Funcion para registrar usuarios en la DB, por defecto pedira al usuario su informacion de registro pero tambien tenemos la opcion de registrar usuarios manualmente desde el propio codigo
def register_user(user_name='', passwd='', cryp_key='', autocomplete=True):
    try:
        if autocomplete:
            os.system('cls')
            print(' Registro de usuario: ')
            #Pide los datos al usuario
            while True:
                user_name = str(input(' Nombre de usuario: '))
                #Si el usuario se equivoca al poner su contraseña y no coincide la volvera a pedir
                while True:
                    passwd = str(getpass(' Contraseña: '))
                    passwd_re = str(getpass(' Repita su contraseña: '))
                    if passwd != passwd_re: 
                        print('\n Las contraseñas no coinciden')
                        continue
                    else: break
                # Pide la key de encriptacion para el regitro
                its_ok = input(' Posee una key de encriptación? (y/n): ').lower()
                if its_ok == 'y' or its_ok == 's' or its_ok == 'yes' or its_ok == 'si':
                    print(f' Seleccione su key de encriptación: ', end='')
                    cryp_key = askopenfilename(title='Seleccione su key de encriptación')
                    print(cryp_key)
                    break
                elif its_ok == 'n' or its_ok == 'no' or its_ok == 'nou' or its_ok == '':
                    print(' Se va a generar una key de encriptacion para su registro, no la pierda')
                    generate_key()
                    print(f' Seleccione su key de encriptación: ', end='')
                    cryp_key = askopenfilename(title='Seleccione su key de encriptación')
                    print(cryp_key)
                    break
                else: 
                    print(' No has introducido una opción valida')
                    continue
                
            while True:
                its_ok = input(' La informacion proporcionada es correcta? (y/n): ').lower()
                if its_ok == 'y' or its_ok == 's' or its_ok == 'yes' or its_ok == 'si':
                    passwd = hash(passwd)
                    cryp_key = hash(read_key(cryp_key), mode='SHA256')
                    # Registra al usuario en la DB
                    db = sqlite3.connect('.storage/users.db')
                    db.execute("insert into users(user_name,passwd,cryp_key) values (?,?,?)", (user_name,passwd,cryp_key))
                    db.commit()
                    db.close()
                    print('\n Usuario registrado correctamente')
                    time.sleep(2)
                    break
                elif its_ok == 'n' or its_ok == 'no' or its_ok == 'nou' or its_ok == '':
                    print(' El registro de usuario no se ha completado')
                    break
                else: 
                    print(' El registro de usuario no se ha completado')
                    break
        
    except: 
        print(' Algo a salido mal al registrar el usuario: ')
        print(Exception)
        time.sleep(2)



#Funcion para crear la base de datos y registrar al primer usuario que sera siempre el administrador
def create_DB():
    db = sqlite3.connect('.storage/users.db')
    try:
        #Creamos la base de datos con los campos necesarios
        db.execute("""create table if not exists users (
                              id integer primary key autoincrement,
                              user_name text not null,
                              passwd txt not null,
                              cryp_key txt not null)""")
        db.execute("""create table if not exists passwd (
                              id integer not null,
                              desc txt not null,
                              passwd txt not null)""")
    except sqlite3.OperationalError:
        db.close()
        print(' Ya existe una base de datos')
        return 'La tabla ya existe'                   
    db.close()
    register_user()

def login(trys=3):
    try:
        db = sqlite3.connect('.storage/users.db')
        data = db.execute('select id from users').fetchone()
        if data==None:
                print(' No se ha detectado ningun admisitrador, se registrara usted como admin [Presiona ENTER para continuar]')
                db.close()
                input()
                create_DB()
                menu_start()
        else:
            global user_name, cryp_key
            os.system('cls')
            print(' Inicio de sesion:')
            print(f' Tienes {trys} intentos antes de que se cierre el programa\n')
            if trys==0:
                print(' Te has quedado sin intentos :´(')
                time.sleep(2)
                exit()

            user_name = str(input(' Nombre de usuario: '))
            passwd = str(getpass(' Contraseña: '))
            cryp_key = askopenfilename(title='Seleccione su key de encriptación')
            print(f' Seleccione su key de encriptación: {cryp_key}')

            data = db.execute('select * from users where user_name=? AND passwd=? AND cryp_key=?', (user_name, hash(passwd), hash(read_key(cryp_key), mode='SHA256'))).fetchone()
            if data==None:
                print(' La informacion proporcionada es incorrecta')
                trys-=1
                time.sleep(2)
                login(trys=trys)
            else:
                print(' Login exitoso')
                try:
                    shutil.copyfile(cryp_key, '.cache/user.key')
                except: pass
                time.sleep(2)
                if data[0]==1:
                    menu_admin()
                else:
                    menu_user()
    except sqlite3.OperationalError: 
        print(' No se ha detectado ningun admisitrador, se registrara usted como admin [Presiona ENTER para continuar]')
        input()
        create_DB()

#----------------------------------------------PASSWD----------------------------------------------
def save_passwd(passwd=''):
    db = sqlite3.connect('.storage/users.db')
    os.system('cls')
    print(' Guardado de contraseña: ')
    user_id = db.execute('select id from users where user_name=?', (user_name, )).fetchone()
    user_id = user_id[0]
    while True:
        desc = str(input(' Introduzca la descripcion de la contraseña (ej: Contraseña de twt): '))
        if passwd=='':
            passwd = str(input(' Introduce la contraseña que deseas guardar: '))
        else:
            print(f' Introduce la contraseña que deseas guardar: {passwd}')
        passwd = cif_txt(passwd)
        its_ok = input(' La informacion proporcionada es correcta? (y/n): ').lower()
        if its_ok == 'y' or its_ok == 's' or its_ok == 'yes' or its_ok == 'si':
            db.execute("insert into passwd(id,desc,passwd) values (?,?,?)", (user_id, desc, passwd))
            db.commit()
            db.close()
            print('\n Contraseña guardada correctamente')
            time.sleep(2)
            break
        elif its_ok == 'n' or its_ok == 'no' or its_ok == 'nou' or its_ok == '':
            print(' OK :)')
            break
        else: 
            print(' No has introducido una opción valida')
            continue

    

def view_passwd():
    db = sqlite3.connect('.storage/users.db')
    os.system('cls')
    print(' Tus contraseñas almacenadas son: \n')
    user_id = db.execute('select id from users where user_name=?', (user_name, )).fetchone()
    user_id = user_id[0]
    data = db.execute('select desc,passwd from passwd where id=?', (user_id, ))
    for fila in data:
        print(f' Descripcion: {fila[0]} | Contraseña: {descif_txt(fila[1])}')
    db.close()
    getpass('\n [Presiona ENTER para volver]')
    
#----------------------------------------------MENUS----------------------------------------------

# Funcion que detecta el tema actual y lo cambia al contrario
theme = "oscuro"
theme_code = '0F'
def change_theme():
    global theme
    global theme_code
    while True:
        os.system('cls')
        print('\n Opciones: ')
        print(f'''
            [+] 1. Tema Claro
            [+] 2. Tema Oscuro
            [+] 3. Tema hacker BlackHat
            [+] 4. Tema hacker GrayHat
            [+] 5. Tema hacker WhiteHat
            ''')
        try:
            option = int(input(' Que deseas realizar: '))
            break
        except ValueError:
            print(" Has introducido una opcion invalida")
            time.sleep(2)
            pass
    if option == 1:
        os.system('color F0')
        theme = "claro"
        theme_code = 'F0'
    elif option==2:
        os.system('color 0F')
        theme = "oscuro"
        theme_code = '0F'
    elif option==3:
        os.system('color 02')
        theme = "hacker BlackHat"
        theme_code = '02'
    elif option==4:
        os.system('color 8A')
        theme = "hacker GrayHat"
        theme_code = '8A'
    elif option==5:
        os.system('color 7A')
        theme = "hacker WhiteHat"
        theme_code = '7A'
    else: 
        print(" Has introducido una opcion invalida")
        time.sleep(3)
    with open('.storage/theme.dat', 'w') as file:
        file.write(theme_code)
        file.close()

def menu_admin():
    global user_name, cryp_key
    while True:
        os.system('cls')
        print(f' Usuario: {user_name}                         Sesion: {datetime.date.today()}\n')
        print(' Opciones: ')
        print(f'''
            [+] 1. Guardar una nueva contraseña
            [+] 2. Consultar contraseñas
            [+] 3. Registrar un nuevo usuario 
            [+] 4. Generar una contraseña segura
            [+] 5. Ver historial de contraseñas generadas
            [+] 6. Cerrar sesion (Recomendado)

            [+] 0. Cambiar tema (Actual: {theme})
            ''')
        try:
            option = int(input(' Que deseas realizar: '))
            break
        except ValueError: 
            print(" Has introducido una opcion invalida")
            time.sleep(2)
            pass
    if option == 1:
        save_passwd()
        menu_admin()
    elif option==2:
        view_passwd()
        menu_admin()
    elif option==3:
        register_user()
        menu_admin()
    elif option==4:       # Generar una contraseña
        try:
            long = int(input(' Longitud de la contraseña a generar: '))
            if long>50:
                print(' La contraseña mas larga que se puede generar es de 50 caracteres')
                time.sleep(3)
                random_passwd(long=50, save=True)
            else:
                random_passwd(long, save=True)
        except:
            print(' No ha introducido un numero valido, se generara una por defecto de 20 caracteres')
            time.sleep(2)
            random_passwd(save=True)
        menu_admin()
    elif option==5:
        os.system('cls')
        print(' Contraseñas generadas anteriormente:\n')
        try:
            with open('.cache/passwd_history', 'r') as file:
                data = file.read()
                print(data)
        except FileNotFoundError:
            print(' No hay ninguna contraseña en el historial\n')
        getpass('\n [Presiona ENTER para volver]')
        menu_admin()
    elif option==6:
        menu_start()
    elif option==0:
        change_theme()
        menu_admin()
    else: 
        print(" Has introducido una opcion invalida")
        time.sleep(3)
        menu_admin()
def menu_user():
    global user_name, cryp_key
    while True:
        os.system('cls')
        print(f' Usuario: {user_name}                         Sesion: {datetime.date.today()}\n')
        print(' Opciones: ')
        print(f'''
            [+] 1. Guardar una nueva contraseña
            [+] 2. Consultar contraseñas
            [+] 3. Generar una contraseña segura
            [+] 4. Ver historial de contraseñas generadas
            [+] 5. Cerrar sesion (Recomendado)

            [+] 0. Cambiar tema (Actual: {theme})
            ''')
        try:
            option = int(input(' Que deseas realizar: '))
            break
        except ValueError: 
            print(" Has introducido una opcion invalida")
            time.sleep(2)
            pass
    if option == 1:
        save_passwd()
        menu_user()
    if option==2:
        view_passwd()
        menu_user()
    elif option==3:       # Generar una contraseña
        try:
            long = int(input(' Longitud de la contraseña a generar: '))
            random_passwd(long, save=True)
        except:
            print(' No ha introducido un numero valido, se generara una por defecto de 20 caracteres')
            time.sleep(2)
            random_passwd(save=True)
        menu_user()
    elif option==4:
        os.system('cls')
        print(' Contraseñas generadas anteriormente:\n')
        try:
            with open('.cache/passwd_history', 'r') as file:
                data = file.read()
                print(data)
        except FileNotFoundError:
            print(' No hay ninguna contraseña en el historial\n')
        getpass('\n [Presiona ENTER para volver]')
        menu_user()
    elif option==5:
        menu_start()
    elif option==0:
        change_theme()
        menu_user()
    else: 
        print(" Has introducido una opcion invalida")
        time.sleep(3)
        menu_user()

def menu_start():
    shutil.rmtree('.cache', ignore_errors=True)
    try:
        os.mkdir('.cache')
        os.mkdir('.storage')
    except FileExistsError: pass
    try:
        os.system('attrib +h .cache')
        os.system('attrib +h .storage')
    except: pass
    while True:
        os.system('cls')
        os.system('title Passwd Master - Powered by Rubio')
        print('\n Opciones: ')
        print(f'''
            [+] 1. Inicio de sesion
            [+] 2. Crear una key de encriptacion aleatoria
            [+] 3. Importar base de datos
            [+] 4. Salir del programa

            [+] 0. Cambiar tema (Actual: {theme})
            ''')
        try:
            option = int(input(' Que deseas realizar: '))
            break
        except ValueError:
            print(" Has introducido una opcion invalida")
            time.sleep(2)
            pass
    if option == 1:
        login()
        menu_start()
    elif option==2:
        generate_key()
        menu_start()
    elif option==3:
        print(" Importar una base de datos")
    elif option==4:
        print(' Bye :)')
        time.sleep(0.5)
        exit()
    elif option==0:
        change_theme()
        menu_start()
    else: 
        print(" Has introducido una opcion invalida")
        time.sleep(3)
        menu_start()

if  __name__=='__main__':
    try:
        with open('.storage/theme.dat', 'r') as f:
            theme_code = f.read()
            f.close()
    except FileNotFoundError: pass
    os.system(f'color {theme_code}')
    menu_start()