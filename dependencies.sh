#!/bin/bash

os=$(uname -o | cut -f1)
arch=$( uname -m  | cut -f1)

function main {
    chmod u+x   ~/Hash_crack/crunch.sh  ~/Hash_crack/dependencies.sh  ~/Hash_crack/crunch  ~/Hash_crack/Hasher.py
    echo "Installing dependencies"
    sleep 2
    if [ "$os" = 'Android' ] ; then
       apt install python3 python-pip -y
       python3 -m pip install pyfiglet requests termcolor rarfile colorama pycryptodome
       echo $(clear)
    else
       sudo apt install python3 python3-pip -y
       python3 -m pip install pyfiglet requests termcolor rarfile colorama pycryptodome
       echo $(clear)      
    fi
         
    if [ "$arch" != 'aarch64' ] ; then
         if [ "$os" = 'Android' ] ; then
           apt install crunch -y
           echo $(clear)
           echo "¡Ready! Everything is now set up"
           
         else
           sudo apt install crunch -y
           echo $(clear)
           echo "¡Ready! Everything is now set up"
           
         fi 
    else
        if [ "$os" = 'Android' ] ; then
           cp -f ~/Hash_crack/crunch  $PATH/
           echo "The system supports the Hash_crack directory crunch"
           
         else
           sudo apt install crunch -y
           echo "!Ready! Everything is now set up"
           
         fi
    fi

}
main
 
