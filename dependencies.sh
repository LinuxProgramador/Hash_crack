#!/bin/bash

os=$(uname -o | cut -f1)
arch=$( uname -m  | cut -f1)

function main {
    chmod u+x   ~/Hash_crack/crunch.sh  ~/Hash_crack/dependencies.sh  ~/Hash_crack/crunch  ~/Hash_crack/Hasher.py
    echo -e "\033[1;34minstalling dependencies"
    echo -e "\033[1;37m"
    sleep 2
    if [ "$os" = 'Android' ] ; then
       apt install python3 python-pip -y
       pip install pyfiglet requests termcolor rarfile colorama pycryptodome
       echo $(clear)
    elif [ "$os" = 'GNU/Linux' ] ; then
       
         
    if [ "$arch" != 'aarch64' ] ; then
           apt install crunch -y
           echo $(clear)
           echo -e "\033[1;34¡Ready! Everything is now set up"
           echo -e "\033[1;37m"

    else
        cp -f /data/data/com.termux/files/home/Hash_crack/crunch  $PATH/
        echo -e "\033[1;34mThe system supports the Hash_crack directory crunch"
        echo -e "\033[1;37m"
    fi

}
main
