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
       python3 -m pip install pyfiglet requests termcolor rarfile colorama pycryptodome
       echo $(clear)
    elif [ "$os" = 'GNU/Linux' ] ; then
       sudo apt install python3 python3-pip -y
       python3 -m pip install pyfiglet requests termcolor rarfile colorama pycryptodome
       echo $(clear)
    else
      echo "system does not support"
      exit
    fi
         
    if [ "$arch" != 'aarch64' ] ; then
         if [ "$os" = 'Android' ] ; then
           apt install crunch -y
           echo $(clear)
           echo -e "\033[1;34¡Ready! Everything is now set up"
           echo -e "\033[1;37m"
         else
           sudo apt install crunch -y
           echo $(clear)
           echo -e "\033[1;34¡Ready! Everything is now set up"
           echo -e "\033[1;37m"
         fi 
    else
        if [ "$os" = 'Android' ] ; then
           cp -f ~/Hash_crack/crunch  $PATH/
           echo -e "\033[1;34mThe system supports the Hash_crack directory crunch"
           echo -e "\033[1;37m"
         else
           cp -f ~/Hash_crack/crunch  /usr/bin
           echo -e "\033[1;34mThe system supports the Hash_crack directory crunch"
           echo -e "\033[1;37m"
         fi
    fi

}
main
 
