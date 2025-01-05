Descargo de responsabilidad:
Esta herramienta ha sido creada exclusivamente con fines educativos. El autor no se responsabiliza por el mal uso que se le pueda dar.

Proyectos de terceros incluidos:

zipcrack: https://github.com/machine1337/zipcrack

RARNinja: https://github.com/SHUR1K-N/RARNinja-RAR-Password-Cracking-Utility

Enlace de descarga del diccionario Rockyou 2023: https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt&ved=2ahUKEwjL6oTfvdKKAxUdSDABHe3UMvwQFnoECBoQAQ&usg=AOvVaw3snAERl1mU6Ccr4WFEazBd

Nota: (bcrypt/sha256crypt/sha512crypt/rypemd-160/wpa-psk) son hashes lentos, es por eso que el tiempo de descifrado tiende a ser mas

Instalación:

cd ~

git clone https://github.com/LinuxProgramador/Hash_crack

cd Hash_crack

bash dependencies.sh

python3 Hasher.py

Para acceder al menú de ayuda y parámetros de opciones:

python3 Hasher.py [-h,--help,-sk,-sk2,-wpk]

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

    WPA-PSK 


Notas importantes:

1. Si deseas utilizar tu propio diccionario, debes llamarlo wordlist.txt y colocarlo en el directorio Hash_crack.


2. El éxito al descifrar contraseñas de archivos ZIP y RAR depende en gran medida del programa utilizado para comprimirlos. Es más probable que el descifrado funcione si se comprimieron utilizando herramientas de consola como zip o rar.


Salir del programa:
Presiona CTRL + C
