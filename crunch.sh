echo $(clear)
echo "ingrese sus tres palabras para el diccionario concatenado"

read -p "ingrese su primera palabra: " palabra1

read -p "ingrese su segunda palabra: " palabra2

read -p "ingrese su tercera palabra: " palabra3
echo $(clear)


crunch 1 1 -o ~/Hash_crack/wordlist.txt -p $palabra1 $palabra2 $palabra3
sleep 2
echo $(clear)
