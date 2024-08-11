echo $(clear)
echo "Enter your three words for the concatenated dictionary"

read -p "Enter your first word: " palabra1

read -p "Please enter your second word: " palabra2

read -p "Please enter your third word: " palabra3
echo $(clear)


crunch 1 1 -o ~/Hash_crack/wordlist.txt -p $palabra1 $palabra2 $palabra3
sleep 2
echo $(clear)
echo "Now run the Hasher.py program again"
