#!/bin/bash


system=$( uname -m  | cut -f1)

function main {
    chmod u+x   ~/Hash_crack/crunch.sh  ~/Hash_crack/dependencies.sh  ~/Hash_crack/crunch  ~/Hash_crack/Hasher.py
    echo -e "\033[1;34minstalando dependencias"
    echo -e "\033[1;37m"
    sleep 2
    apt install python3 python-pip -y
    pip install pyfiglet requests termcolor rarfile colorama
    echo $(clear)

    if [ "$system" != 'aarch64' ] ; then
           apt install crunch -y
           echo $(clear)
           echo -e "\033[1;34¡Listo! ya todo esta configurado"
           echo -e "\033[1;37m"

    else
        cp -f /data/data/com.termux/files/home/Hash_crack/crunch  $PATH/
        echo -e "\033[1;34mEl sistema es compatible con el crunch del directorio Hash_crack"
        echo -e "\033[1;37m"
    fi

}
main
