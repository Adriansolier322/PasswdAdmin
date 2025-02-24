# Author: Adrián Fernández Álvarez

# Cryptography
from Cryptodome.Hash import MD5, SHA256
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
import Cryptodome.Random
import base64

# Socket
import socket

#GUI
import tkinter as tk
from tkinter.filedialog import askopenfilename, askdirectory
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
def cif_txt(txt, user_id=0, is_role=False):
    if is_role:
        key = read_key(db_key_name='roles', id=user_id, RSA_mode=True)
    else:
        key = read_key(db_key_name='pub_keys', id=user_id, RSA_mode=True)
    cipher = PKCS1_OAEP.new(key)
    txt_cif = cipher.encrypt(txt.encode())
    return base64.b64encode(txt_cif).decode('utf-8')

# Función para descifrar el texto
def descif_txt(txt_cif, user_name='', is_role=False):
    if is_role:
        pass
    else:
        key = read_key(path=f'.cache/keys/{user_name}_priv.keypa', RSA_mode=True)
    txt_cif = base64.b64decode(txt_cif)
    cipher = PKCS1_OAEP.new(key)
    txt_descif = cipher.decrypt(txt_cif)
    return txt_descif.decode('utf-8')

def search_keys():
    os.system('dir /b/s *.keypa > .cache/found_keys')

#----------------------------------------------Others----------------------------------------------

# Función para generar y guardar la clave en un archivo
def generate_key(user_id=0, user_name='user', key_directory='', role_name=''):
    random = Cryptodome.Random.new().read
    priv_key = RSA.generate(1024, random)
    pub_key = priv_key.publickey()
    priv_key = priv_key.exportKey(format='DER')
    pub_key = pub_key.exportKey(format='DER')

    db = sqlite3.connect('.storage/users.db')
    if key_directory=='':
        key_directory = askdirectory(title='Selecione la carpeta donde se guardaran las keys')
        open(f'{key_directory}/{user_name}_priv.keypa', 'wb').write(base64.b64encode(priv_key))
        db.execute("insert into pub_keys(id,pub_key,priv_key) values (?,?,?)", (user_id,base64.b64encode(pub_key),hash(base64.b64encode(priv_key))))
    else:
        open(f'{key_directory}/{role_name}_priv.keypa', 'wb').write(base64.b64encode(priv_key))
        db.execute("insert into roles(role_name,pub_key,priv_key) values (?,?,?)", (role_name,base64.b64encode(pub_key),hash(base64.b64encode(priv_key))))
    db.commit()
    db.close()
    return key_directory

#Funcion para leer la key de encriptacion
def read_key(id=0, path='.cache/user_priv.keypa', db_key_name='', RSA_mode=False):
    if db_key_name!='':
        db = sqlite3.connect('.storage/users.db')
        data = db.execute(f'select pub_key from {db_key_name} where id=?', (id, )).fetchone()
        data = data[0]
        db.close()
    else:
        with open(path, 'rb') as file:
            data = file.read()
            file.close()
    if RSA_mode:
        return RSA.importKey(base64.b64decode(data))
    else:
        return base64.b64decode(data)
        
#----------------------------------------------SERVER----------------------------------------------


def download_db():
    print(" 📡 Descargando base de datos al servidor (no cierre el programa)...")
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((SERVER_IP, PORT))
        client.sendall(b"DOWNLOAD")
        data = client.recv(1024)
        if data==b"ERROR: No existe ninguna base de datos en el servidor o la tiene otro usuario.":
            print(' ❌ ERROR: No existe ninguna base de datos en el servidor o la tiene otro usuario.')
            time.sleep(2)
        else:
            with open(DB_FILENAME, "wb") as db_file:
                while True:
                    db_file.write(data)
                    data = client.recv(4096)
                    if not data:
                        break
                
            print(" ✅ Base de datos descargada correctamente.")
        client.close()

    except Exception as e:
        print(f" ❌ Error al descargar la base de datos: {e}")
    time.sleep(2)

def upload_db():
    print(" 📡 Subiendo base de datos al servidor (no cierre el programa)...")
    try:
        if not os.path.exists(DB_FILENAME):
            print(" ⚠️ No hay base de datos para subir.")
            return

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((SERVER_IP, PORT))
        client.sendall(b"UPLOAD")
        time.sleep(1)

        with open(DB_FILENAME, "rb") as db_file:
            while chunk := db_file.read(4096):
                client.sendall(chunk)

        print(" ✅ Base de datos subida correctamente.")
        client.close()

    except Exception as e:
        print(f" ❌ Error al subir la base de datos: {e}")
    time.sleep(2)

def conf_server(check=False, complete=False):
    global PORT, DB_FILENAME, SERVER_IP
    PORT = 2222
    DB_FILENAME = ".storage/users.db"
    try:
        with open(".storage/server_ip.dat", "r") as f:
            SERVER_IP = f.read()
        Pass=True
    except FileNotFoundError:
        Pass=False
    if check: return Pass
    if complete:
        while True:
            os.system('cls')
            print(' 🛜 Configuracion de servidor remoto:\n')
            SERVER_IP = str(input(' Introduzca la ip o direccion del servidor remoto: '))

            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((SERVER_IP, PORT))
                print(' ✅ Conexion exitosa')
                with open(".storage/server_ip.dat", "w") as f:
                    f.write(SERVER_IP)
                time.sleep(2)
                download_db()
            except Exception as e:
                print(f" ❌ El servidor no responde: {e}")
                its_ok = input(' Deseas volver a intentarlo? (y/n): ').lower()
                if its_ok == 'y' or its_ok == 's' or its_ok == 'yes' or its_ok == 'si':
                    continue
                else: 
                    print(' Prodra configurar el servidor en cualquier momento')
                    time.sleep(2)
                    break


#----------------------------------------------DB----------------------------------------------

#Funcion para registrar usuarios en la DB, por defecto pedira al usuario su informacion de registro pero tambien tenemos la opcion de registrar usuarios manualmente desde el propio codigo
def register_user(user_name='', passwd='', priv_key='', autocomplete=True):
    #try:
        if autocomplete:
            db = sqlite3.connect('.storage/users.db')
            os.system('cls')
            print(' 👤 Registro de usuario: \n')
            #Pide los datos al usuario
            while True:
                user_name = str(input(' Nombre de usuario: '))
                try:
                    db_username = db.execute('select user_name from users where user_name=?', (user_name, )).fetchone()
                    db_username = db_username[0]
                    if user_name==db_username:
                        print('\n Ya existe un usuario con ese nombre, elija otro')
                        continue
                except: pass
                #Si el usuario se equivoca al poner su contraseña y no coincide la volvera a pedir
                while True:
                    passwd = str(getpass(' Contraseña: '))
                    passwd_re = str(getpass(' Repita su contraseña: '))
                    if passwd != passwd_re: 
                        print('\n Las contraseñas no coinciden')
                        continue
                    else: break
                
                try:
                    user_id = db.execute("select id from users ORDER BY id DESC LIMIT 1").fetchone()
                    user_id = user_id[0]
                    user_id+=1
                    
                except:
                    user_id=1
                    
                print(' Se va a generar una key de encriptacion para su registro, no la pierda')
                print(' Su key se encuentra en: ', end='')
                key_directory = generate_key(user_id=user_id, user_name=user_name)
                print(key_directory)
                if user_id==1:
                    generate_key(key_directory=key_directory, role_name='admin')
                    role=1
                else:
                    generate_key(key_directory=key_directory, role_name='ninguno')
                    role=2
                break
    
                
            its_ok = input(' La informacion proporcionada es correcta? (y/n): ').lower()
            if its_ok == 'y' or its_ok == 's' or its_ok == 'yes' or its_ok == 'si':
                passwd = hash(passwd)
                priv_key = hash(read_key(path=f'{key_directory}/{user_name}_priv.keypa'), mode='SHA256')
                # Registra al usuario en la DB
                db.execute("insert into users(user_name,passwd,priv_key,keys_directory,role) values (?,?,?,?,?)", (user_name,passwd,priv_key,key_directory,role))
                db.commit()
                db.close()
                print('\n ✅ Usuario registrado correctamente')
                time.sleep(2)
            elif its_ok == 'n' or its_ok == 'no' or its_ok == 'nou' or its_ok == '':
                print(' ❌ El registro de usuario no se ha completado')
                time.sleep(2)
            else: 
                print(' ❌ El registro de usuario no se ha completado')
                time.sleep(2)

        
    #except: 
    #    print('\n Algo a salido mal al registrar el usuario')
    #    time.sleep(2)

def login(trys=3):
    try:
        db = sqlite3.connect('.storage/users.db')
        data = db.execute('select id from users').fetchone()
        if data==None:
                print(' No se ha detectado ningun admisitrador, se registrara usted como admin')
                db.close()
                getpass('\n [Presiona ENTER para continuar]')
                create_DB()
                menu_start()
        else:
            global user_name, priv_key, role
            os.system('cls')
            print(' 🎫 Inicio de sesion:')
            print(f' Tienes {trys} intentos antes de que se cierre el programa\n')
            if trys==0:
                print(' ❌ Te has quedado sin intentos :´(')
                time.sleep(2)
                exit()

            user_name = str(input(' Nombre de usuario: '))
            passwd = str(getpass(' Contraseña: '))
            print(f' Seleccione su key de encriptación: ', end='')
            priv_key = askopenfilename(title='Seleccione su key de encriptación')
            print(priv_key)

            data = db.execute('select * from users where user_name=? AND passwd=? AND priv_key=?', (user_name, hash(passwd), hash(read_key(path=priv_key), mode='SHA256'))).fetchone()
            if data==None:
                print(' ❌ La informacion proporcionada es incorrecta')
                trys-=1
                time.sleep(2)
                login(trys=trys)
            else:
                print(' ✅ Inicio de sesion exitoso')
                role_id = data[5]
                role = db.execute('select role_name from roles where id=?', (role_id, )).fetchone()
                role = role[0]
                try:
                    keys_directory = data[4]
                    shutil.copytree(keys_directory, '.cache/keys')
                except: pass
                time.sleep(2)
                if data[0]==1:
                    menu_admin()
                else:
                    menu_user()
    except sqlite3.OperationalError: 
        print(' No se ha detectado ningun admisitrador, se registrara usted como admin')
        getpass('\n [Presiona ENTER para continuar]')
        create_DB()


#Funcion para crear la base de datos y registrar al primer usuario que sera siempre el administrador
def create_DB():
    db = sqlite3.connect('.storage/users.db')
    try:
        #Creamos la base de datos con los campos necesarios
        # Tabla usuarios
        db.execute("""create table if not exists users (
                            id integer primary key autoincrement,
                            user_name text not null,
                            passwd txt not null,
                            priv_key txt not null,
                            keys_directory txt not null,
                            role txt not null,
                            foreign key (role) references roles (id))""")
        # Tabla roles
        db.execute("""create table if not exists roles (
                            id integer primary key autoincrement,
                            role_name txt not null,
                            pub_key txt not null,
                            priv_key txt not null)""")
        # Tabla contraseñas privadas
        db.execute("""create table if not exists priv_passwd (
                            id integer not null,
                            desc txt not null,
                            passwd txt not null,
                            foreign key (id) references users (id))""")
        # Tabla contraseñas publicas
        db.execute("""create table if not exists pub_passwd (
                            desc txt not null,
                            passwd txt not null,
                            role integer not  null,
                            foreign key (role) references roles (id))""")
        # Tabla keys publicas
        db.execute("""create table if not exists pub_keys (
                            id integer,
                            pub_key txt not null,
                            priv_key txt not null,
                            foreign key (id) references users (id))""")
        
    except sqlite3.OperationalError:
        print(' ❌ Ya existe una base de datos')            
    db.close()
    register_user()


#----------------------------------------------PASSWD----------------------------------------------
# Guarda la contraseña privada en la base de datos, preguntando la descripcion
def save_passwd(passwd='', role=['admin'], is_pub_passwd=False):
    db = sqlite3.connect('.storage/users.db')
    os.system('cls')
    print(' 🔑 Guardado de contraseña: ')
    user_id = db.execute('select id from users where user_name=?', (user_name, )).fetchone()
    user_id = user_id[0]
    while True:
        desc = str(input(' Introduzca la descripcion de la contraseña (ej: Contraseña de twt): ')).lower()
        if is_pub_passwd:
            data = db.execute('select desc from pub_passwd where desc=?', (desc, )).fetchone()
            if data==None:
                pass
            else:
                data = data[0]
        else:
            data = db.execute('select desc from priv_passwd where desc=?', (desc, )).fetchone()
            if data==None:
                pass
            else:
                data = data[0]
        if desc=='exit':
            print(' ❌ La descripcion de la contraseña no puede ser "exit"')
            continue
        elif desc==data:
            print(' ❌ Ya existe una contraseña con esa descripcion, porfavor use otra')
            continue
        elif len(desc)>100:
            print(' ❌ La descripcion no puede tener mas de 100 caracteres') 
            continue
        else:
            if passwd=='':
                its_ok = input(' Deseas generar la contraseña aleatoriamente? (y/n): ').lower()
                if its_ok == 'y' or its_ok == 's' or its_ok == 'yes' or its_ok == 'si':
                    passwd = random_passwd(30)
                else: 
                    while True:
                        passwd = str(input(' Introduce la contraseña que deseas guardar: '))
                        if len(passwd)>100:
                            print(' ❌ La contraseña no puede tener mas de 100 caracteres')
                            continue
                        else: break
            else:
                print(f' Introduce la contraseña que deseas guardar: {passwd}')
            
            if is_pub_passwd:
                passwd = cif_txt(passwd, user_id)
            else:
                passwd = cif_txt(passwd, user_id)

            its_ok = input('\n Estas seguro de que deseas guardar esta contraseña? (y/n): ').lower()
            if its_ok == 'y' or its_ok == 's' or its_ok == 'yes' or its_ok == 'si':
                if is_pub_passwd:
                    db.execute("insert into pub_passwd(desc,passwd,role) values (?,?,?)", (user_id, desc, role))
                else:
                    db.execute("insert into priv_passwd(id,desc,passwd) values (?,?,?)", (user_id, desc, passwd))
                    db.commit()
                    db.close()
                    print('\n ✅ Contraseña guardada correctamente')
                    time.sleep(2)
                    break
            elif its_ok == 'n' or its_ok == 'no' or its_ok == 'nou' or its_ok == '':
                print(' ❌ OK :)')
                break
            else: 
                print(' ❌ No has introducido una opción valida')
                continue

    
# Muestra las contraseñas almacenadas en la base de datos y si delete=True le preguntara al usuario que contraseña desea eliminar y eliminara la que elija el usuario
def view_passwd(delete=False):
    global user_name
    db = sqlite3.connect('.storage/users.db')
    os.system('cls')
    print(' 📋 Tus contraseñas almacenadas son: \n')
    user_id = db.execute('select id from users where user_name=?', (user_name, )).fetchone()
    user_id = user_id[0]
    data = db.execute('select desc,passwd from priv_passwd where id=?', (user_id, ))
    for fila in data:
        print(f' Descripcion: {fila[0]} | Contraseña: {descif_txt(fila[1], user_name)}\n')
    
    if delete:
        print('-------------------------------------------------------------------------------------------------------')
        while True:
            answer = str(input('\n Introduce la descripcion de la contraseña que deseas eliminar (escribe "exit" para salir): ')).lower()
            if answer=='exit':
                break
            delete_passwd = db.execute('select desc from priv_passwd where desc=?',  (answer, )).fetchone()
            if delete_passwd==None:
                print(' ❌ La contraseña que buscas no existe')
            else:
                os.system('cls')
                print(' 🗑️ La contraseña que se va a eliminar es la siguiente: \n')
                
                delete_passwd = db.execute('select desc,passwd from priv_passwd where desc=?', (answer, )).fetchone()
                print(f' Descripcion: {delete_passwd[0]} | Contraseña: {descif_txt(delete_passwd[1], user_name)}\n')

                its_ok = input('\n Estas seguro? (y/n): ').lower()
                if its_ok == 'y' or its_ok == 's' or its_ok == 'yes' or its_ok == 'si':
                    db.execute('delete from priv_passwd where desc=?', (delete_passwd[0], ))
                    db.commit()
                    print(' ✅ Contraseña eliminada con exito')
                    time.sleep(2)
                    break
                elif its_ok == 'n' or its_ok == 'no' or its_ok == 'nou' or its_ok == '':
                    print(' ❌ OK :)')
                    break
                else: 
                    print(' ❌ No has introducido una opción valida')
                    continue
        db.close()
    else:
        db.close()
        getpass('\n [Presiona ENTER para volver]')

# Funcion que crea una contraseña aleatoria segun un largo dado que por defecto es 20 y la guarda en la base de datos si el usuario lo requiere
def random_passwd(long=20, save=False):
    caracters = [i for i in string.printable]
    passwd = ''
    # Se genera la contraseña de forma pseudoaleatoria
    for i in range(long):
        passwd+=random.choice(caracters[0:94])
    print(f' La contraseña generada es: {passwd}')
    with open('.cache/passwd_history', 'a') as file:
        file.write(' -- | ' + passwd + '\n' + '    |' + '\n')
        file.close()
    # Se guarda en la base de datos si el usuario lo desea
    if save:
        its_ok = input(' Deseas guardar la contraseña en tu base de datos? (y/n): ').lower()
        if its_ok == 'y' or its_ok == 's' or its_ok == 'yes' or its_ok == 'si':
            save_passwd(passwd=passwd)
            pass
        elif its_ok == 'n' or its_ok == 'no' or its_ok == 'nou' or its_ok == '':
            print(' Podras consultar el historial de contraseñas generadas')
            time.sleep(2)
        else: 
            print(' No has introducido una opción valida')
    return passwd

# Funcion para visualizar las contraseñas generadas anteriormente
def passwd_history():
    os.system('cls')
    print(' 📋 Contraseñas generadas anteriormente:\n')
    try:
        with open('.cache/passwd_history', 'r') as file:
            data = file.read()
            print(data)
    except FileNotFoundError:
        print(' ❌ No hay ninguna contraseña en el historial\n')
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
        print('\n 🎨 Seleccion de tema: ')
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
            print(" ❌ Has introducido una opcion invalida")
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
        print(" ❌ Has introducido una opcion invalida")
        time.sleep(3)
    with open('.storage/theme.dat', 'w') as file:
        file.write(theme_code)
        file.close()

def menu_admin():
    global user_name, priv_key, role
    while True:
        os.system('cls')
        print(f' 👤 Usuario: {user_name} | Rol: {role}                    📰 Sesion: {datetime.date.today()}\n')
        print(' Opciones: ')
        print(f'''
            [+] 1. Guardar una nueva contraseña
            [+] 2. Borrar una contraseña
            [+] 3. Consultar contraseñas
            [+] 4. Registrar un nuevo usuario 
            [+] 5. Generar una contraseña segura
            [+] 6. Ver historial de contraseñas generadas
            [+] 7. Cerrar sesion (Recomendado)

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
    elif option==2:
        view_passwd(True)
    elif option==3:
        view_passwd()
    elif option==4:
        register_user()
    elif option==5:       # Generar una contraseña
        try:
            long = int(input(' Longitud de la contraseña a generar: '))
            if long>50:
                print(' La contraseña mas larga que se puede generar es de 50 caracteres')
                random_passwd(long=50, save=True)
            else:
                random_passwd(long, save=True)
        except:
            print(' ❌ No ha introducido un numero valido, se generara una por defecto de 20 caracteres')
            time.sleep(2)
            random_passwd(save=True)
    elif option==6:
        passwd_history()
    elif option==7:
        if conf_server(check=True):
            conf_server()
            upload_db()
        menu_start()
    elif option==0:
        change_theme()
    else: 
        print(" ❌ Has introducido una opcion invalida")
        time.sleep(3)
    menu_admin()

def menu_user():
    global user_name, priv_key, role
    while True:
        os.system('cls')
        print(f' Usuario: {user_name} | Rol:{role}                         Sesion: {datetime.date.today()}\n')
        print(' Opciones: ')
        print(f'''
            [+] 1. Guardar una nueva contraseña
            [+] 2. Borrar una contraseña
            [+] 3. Consultar contraseñas
            [+] 4. Generar una contraseña segura
            [+] 5. Ver historial de contraseñas generadas
            [+] 6. Cerrar sesion (Recomendado)

            [+] 0. Cambiar tema (Actual: {theme})
            ''')
        try:
            option = int(input(' Que deseas realizar: '))
            break
        except ValueError: 
            print(" ❌ Has introducido una opcion invalida")
            time.sleep(2)
            pass
    if option == 1:
        save_passwd()
    elif option==2:
        view_passwd(True)
    elif option==3:
        view_passwd()
    elif option==4:       # Generar una contraseña
        try:
            long = int(input(' Longitud de la contraseña a generar: '))
            random_passwd(long, save=True)
        except:
            print(' ❌ No ha introducido un numero valido, se generara una por defecto de 20 caracteres')
            time.sleep(2)
            random_passwd(save=True)
    elif option==5:
        passwd_history()
    elif option==6:
        if conf_server(check=True):
            conf_server()
            upload_db()
        menu_start()
    elif option==0:
        change_theme()
    else: 
        print(" ❌ Has introducido una opcion invalida")
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
        os.system('cls & title PasswdAdmin - Powered by Rubio & mode con: cols=110 lines=25')
        print('\n 💀 Opciones: ')
        print(f'''
            [+] 1. Inicio de sesion
            [+] 2. Configurar servidor remoto
            [+] 3. Salir del programa

            [+] 0. Cambiar tema (Actual: {theme})
            ''')
        try:
            option = int(input(' Que deseas realizar: '))
            break
        except ValueError:
            print(" ❌ Has introducido una opcion invalida")
            time.sleep(2)
            pass
    if option == 1:
        login()
    elif option==2:
        conf_server(complete=True)
    elif option==3:
        if conf_server(check=True):
            conf_server()
            upload_db()
        print(' Bye :)')
        time.sleep(0.5)
        os.system('cls & color')
        exit()
    elif option==0:
        change_theme()
    else: 
        print(" ❌ Has introducido una opcion invalida")
        time.sleep(3)
    menu_start()

if  __name__=='__main__':
    try:
        with open('.storage/theme.dat', 'r') as f:
            theme_code = f.read()
            f.close()
    except FileNotFoundError: pass
    os.system(f'color {theme_code}')
    if conf_server(check=True):
        download_db()
    menu_start()
   