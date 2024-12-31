Descargo de responsabilidad:
Esta herramienta ha sido creada exclusivamente con fines educativos. El autor no se responsabiliza por el mal uso que se le pueda dar.

Proyectos de terceros incluidos:

zipcrack: https://github.com/machine1337/zipcrack

RARNinja: https://github.com/SHUR1K-N/RARNinja-RAR-Password-Cracking-Utility

Rockyou dictionary download link 2023: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt&ved=2ahUKEwjL6oTfvdKKAxUdSDABHe3UMvwQFnoECBoQAQ&usg=AOvVaw3snAERl1mU6Ccr4WFEazBd

Instalación:

cd ~

git clone https://github.com/LinuxProgramador/Hash_crack

cd Hash_crack

bash dependencies.sh

python3 Hasher.py

Para acceder al menú de ayuda:

python3 Hasher.py [-h,--help]

Hashes soportados:

    MD5

    SHA1

    SHA224

    SHA256

    SHA384

    SHA512

    SHA3-224

    SHA3-256

    SHA3-384

    SHA3-512

    BLAKE2s

    BLAKE2b

    RIPEMD-160

    BCRYPT 

    SHA256CRYPT

    SHA512CRYPT

    SHAKE-128

    SHAKE-256


Notas importantes:

1. Si deseas utilizar tu propio diccionario, debes llamarlo wordlist.txt y colocarlo en el directorio Hash_crack.


2. El éxito al descifrar contraseñas de archivos ZIP y RAR depende en gran medida del programa utilizado para comprimirlos. Es más probable que el descifrado funcione si se comprimieron utilizando herramientas de consola como zip o rar.


Salir del programa:
Presiona CTRL + C
