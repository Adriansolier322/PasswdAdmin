@echo off
title PasswdAdmin-start - Powered by Rubio & mode con: cols=90 lines=25
goto verify
:install_pycryptodomex
echo.
echo La instalacion comenzara en unos instantes...
timeout /nobreak /t 1 > nul 2>&1
pip install pycryptodomex
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Error durante la instalacion de PyCryptodomex.
    echo [Presione cualquier tecla para cerrar el programa]
    pause > nul
    exit /b
)
goto start_program

:no_install
echo.
echo Debera instalar PyCryptodomex para utilizar PasswdAdmin.
echo [Presione cualquier tecla para cerrar el programa]
pause > nul
exit /b

:start_program
start /high /min python PasswdAdmin_server.py
exit /b

:want_install
echo.
echo La dependencia PyCryptodomex no se encuentra instalada.
echo.
set /p input=Desea instalarla ahora? (y/n): 
if /I "%input%"=="y" (goto install_pycryptodomex)
if /I "%input%"=="s" (goto install_pycryptodomex)
if /I "%input%"=="yes" (goto install_pycryptodomex)
if /I "%input%"=="si" (goto install_pycryptodomex)
if "%input%"=="" (goto install_pycryptodomex)
goto no_install

:verify
:: Verificar si Python está instalado
python --version > nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Python no esta instalado o no esta en la variable de entorno PATH.
    echo Por favor, instala Python antes de continuar.
    echo.
    echo [Presione cualquier tecla para cerrar el programa]
    pause > nul
    python
    exit /b
)
python -m pip --version > nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Pip no está instalado o no está en la variable de entorno PATH.
    echo Por favor, instala pip antes de continuar.
    echo.
    echo [Presione cualquier tecla para cerrar el programa]
    pause > nul
    exit /b
)
:: Verificar si pycryptodomex está instalado
python -m pip show pycryptodomex > nul 2>&1
if %ERRORLEVEL% NEQ 0 (goto want_install) else (
    goto start_program
) 