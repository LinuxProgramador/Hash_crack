#!/bin/bash

os=$(uname -o | cut -f1)
arch=$( uname -m  | cut -f1)

function main {
    chmod u+x   ~/Hash_crack/crunch.sh  ~/Hash_crack/dependencies.sh  ~/Hash_crack/crunch  ~/Hash_crack/Hasher.py  ~/Hash_crack/multiprocess2.py  ~/Hash_crack/multiprocess1.py  ~/Hash_crack/brute_force.py  
    echo "Installing dependencies"
    sleep 2
    if [ "$os" = 'Android' ] ; then
       apt install python3 python-pip rust -y
       python3 -m pip install pyfiglet requests termcolor rarfile colorama pycryptodome bcrypt passlib
    else
       sudo apt install python3 python3-pip -y
       python3 -m pip install pyfiglet requests termcolor rarfile colorama pycryptodome bcrypt passlib
    fi
    if [ "$os" = 'Android' ] ; then
       if [ "$arch" = 'aarch64' ] ; then
           cp -f ~/Hash_crack/crunch  $PATH/
           echo $(clear)
           echo "The system supports the Hash_crack directory crunch"
       else
           apt install crunch -y
           echo $(clear)
           echo "¡Ready! Everything is now set up"
       fi
    else
           sudo apt install crunch -y
           echo $(clear)
           echo "¡Ready! Everything is now set up"
    fi
}
main
 
