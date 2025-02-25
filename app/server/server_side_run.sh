#!/bin/bash

if command -v python3 &>/dev/null; then
    echo "Python está instalado. Iniciando PasswdAdmin_server.py en segundo plano..."
    python3 PasswdAdmin_server.py &
else
    echo "Python no está instalado. Intentando instalarlo..."

    if command -v apt &>/dev/null; then
        sudo apt update
        sudo apt install -y python3
        echo "Python ha sido instalado. Iniciando hola.py en segundo plano..."
        python3 PasswdAdmin_server.py &
    else
        echo "No se pudo instalar Python automáticamente. El sistema no tiene apt disponible."
    fi
fi
