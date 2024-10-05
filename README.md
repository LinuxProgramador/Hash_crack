
Descargo de Responsabilidad: Esta herramienta fue creada con fines educativos, no me hago responsable de su mal uso

Proyectos de Terceros incluidos:

1) https://github.com/machine1337/zipcrack
   
2) https://github.com/CiKu370/hasher
   
3) https://github.com/SHUR1K-N/RARNinja-RAR-Password-Cracking-Utility


Instalación:

cd ~

git clone https://github.com/LinuxProgramador/Hash_crack

cd Hash_crack

bash dependencies.sh

python3 Hasher.py

python3 Hasher.py [-h,--help]  muestra el menu de ayuda 

Hash soportados:

    md5
    sha1
    sha224
    sha256
    sha384                                                                     
    sha512      
    sha3_256
    sha3_224
    sha3_384
    sha3_512
    blake2s
    blake2b
    RIPEMD-160

Nota: si quiere importar su propio diccionario tiene que llamarse wordlist.txt y estar dentro del directorio Hash_crack

Nota: descifrar la contraseña en archivos zip y rar depende mucho del programa que los comprimió, es más factible descifrarlos si se comprimieron con zip o rar de consola

zcrack :- crack zip

RARNinja :- crack rar

Para salir del programa presione CTRL C
