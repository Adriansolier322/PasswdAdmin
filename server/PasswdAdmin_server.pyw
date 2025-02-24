# Author: Adrián Fernández Álvarez
# Version: 0.3.0

import socket
import threading
import os


HOST = ''
PORT = 2222
DB_FILENAME = ".storage/users.db"
LOG_FILENAME  = ".storage/logs.log"

def handle_client(conn, addr):
    try:
        request = conn.recv(1024).decode()

        if request == "UPLOAD":
            with open(LOG_FILENAME, "a") as f:
                f.write(f"[{addr}] Recibiendo base de datos...\n")
                f.close()
            with open(DB_FILENAME, "wb") as db_file:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    db_file.write(data)
            with open(LOG_FILENAME, "a") as f:
                f.write(f"[{addr}] Base de datos guardada correctamente.\n")
                f.close()
        elif request == "DOWNLOAD":
            with open(LOG_FILENAME, "a") as f:
                f.write(f"[{addr}] Enviando base de datos al cliente...\n")
                f.close()
            if os.path.exists(DB_FILENAME):
                with open(DB_FILENAME, "rb") as db_file:
                    while chunk := db_file.read(4096):
                        conn.sendall(chunk)
                with open(LOG_FILENAME, "a") as f:
                    f.write(f"[{addr}] Base de datos enviada correctamente.\n")
                    f.close()
                os.remove(DB_FILENAME)
            else:
                conn.sendall(b"ERROR: No existe ninguna base de datos en el servidor o la tiene otro usuario.")
                with open(LOG_FILENAME, "a") as f:
                    f.write(f"[{addr}] ERROR: No existe ninguna base de datos en el servidor o la tiene otro usuario.\n")
                    f.close()


    except Exception as e:
        with open(LOG_FILENAME, "a") as f:
            f.write(f"[{addr}] Error: {e}\n")
            f.close()

    finally:
        conn.close()
        with open(LOG_FILENAME, "a") as f:
            f.write(f" - Conexion cerrada con {addr[0]}\n")
            f.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    with open(LOG_FILENAME, "a") as f:
        f.write(f"\nServidor escuchando en {HOST}:{PORT}\n")
        f.close()

    while True:
        conn, addr = server.accept()
        with open(LOG_FILENAME, "a") as f:
            f.write(f" - Conexion establecida con {addr[0]}\n")
            f.close()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    try:
        os.mkdir('.storage')
        os.system('attrib +h .storage')
    except FileExistsError: pass
    finally:
        start_server()
