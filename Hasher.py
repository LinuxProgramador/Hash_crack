#!/usr/bin/python3

#Herramienta para romper hashes por fuerza bruta en termux

#La herramienta zcrack fue brindada por maquina1337 visita su pagina en github
#https://github.com/machine1337/zipcrack
#El banner fue brindado por CiKu370 visita su pagina en github
#https://github.com/CiKu370/hasher
#La herramienta RARNinja fue brindado por SHUR1K-N visita su pagina en github
#https://github.com/SHUR1K-N/RARNinja-RAR-Password-Cracking-Utility



from hashlib import md5,sha1,sha224,sha384,sha256,sha512,sha3_256,sha3_224,sha3_384,sha3_512,blake2s,blake2b
from sys import argv,exit
from os import system
from time import sleep


class Hash_crack:


  def __init__(self):
    self.md5=len("7e4b64eb65e34fdfad79e623c44abd94")
    self.sha1=len("fb350a3339434d66a5d41d5b4ec073e1f25891c6")
    self.sha224=len("07aa9272511b124aa03950a8324fbbaecd9cb4a534ccd8ad6a033e9d")
    self.sha256=len("23a7b87d4d4e69bbf44b07558b12f39dff5452a80eb60097f1e91ae237583fc9")
    self.sha384=len("c6bafe2a4bdcb52b1f994861f663fa9cf739e84ea53fcce96a5131585b22d6dbb7330825146d38edc7122d64ecc1c534")
    self.sha512=len("eda2d415e59c909a7db89b3e2cd4f44b72c37c79d47e31d37e8e64e3e954ccd182649aa08c2ad3da8a8834abc5d1fbe9297e1833bd2e499c85a85dd97b407e15")
    self.rute_dictionary="/data/data/com.termux/files/home/Hash_crack/wordlist.txt"


  def banner(self):
        print ('\n              Hasher 1.0')
        print ('  ------------------------------------------')
        print ('  88  88    db    .dP"Y8 88  88 88888 88""Yb ')
        print ('  88  88   dPYb   `Ybo." 88  88 88__  88__dP ')
        print ('  888888  dP__Yb  o.`Y8b 888888 88""  88"Yb  ')
        print ('  88  88 dP""""Yb 8bodP  88  88 88888 88  Yb ')
        print ('  ------------------------------------------')
        

  def call_modules(self):
    confirm=input("Do you want to use (zcrack/rarninja/or \"no\" for none ): ").strip().lower()
    if confirm == "zcrack": 
      print("NOTE:This process may take time!") 
      sleep(3) 
      system("python3 /data/data/com.termux/files/home/Hash_crack/zcrack.py")
      exit(2)       
    elif confirm == "rarninja":
      print("NOTE:This process may take time!") 
      sleep(3) 
      system("clear")
      system("python3 /data/data/com.termux/files/home/Hash_crack/RARNinja.py")
      exit(2)      
    
  def crunch(self):
     verificate=input("You want to use the existing dictionary (yes/no): ").strip().lower()
     if verificate == "no":
           system("rm -f /data/data/com.termux/files/home/Hash_crack/wordlist.txt")
           print("We'll use Crunch to generate a new dictionary!")
           sleep(3)
           system("clear")
           print("""
1) create dictionary by concatenating words for example:
   unconcatenated (Harry Hermallony Ron) with concatenate (HarryHermallonyRon) 
   
2) create dictionary specifying a minimum and maximum of characters to use for example:
   (crunch 4 8 abcdef) Here it will generate a minimum of 4 and a maximum of 8 characters using all possible combinations of the abcdef or any other data assigned to it.! 
   
3) create a dictionary with the initial of a password and the rest trying combinations for example:
   qwerty (12345) 
   Note: It is important to emphasize that if the password is hello123 and the initials that you do not know are 123, then put them in @ for example hello@@@ and the exact length for example in this case would be 7
   
NOTE:Be careful with the number of passwords you use. can be generated, it can reach up to gigabytes and block the phone
                  """)
           comand=input("option: ")
           if comand == "1":
                system("bash /data/data/com.termux/files/home/Hash_crack/crunch.sh")
                exit(2)
           elif comand == "2":
                   system("clear")
                   minimo=input("Enter the minimum password: ")
                   maximo=input("Enter the maximum password: ")
                   valores=input("Enter the data to generate the dictionary: ")
                   system("clear")
                   print("Then copy and paste the command that will be given to you into the console and run Hasher.py again.")
                   print(f"crunch {minimo} {maximo} {valores} -o ~/Hash_crack/wordlist.txt")
                   exit(2)
           elif comand == "3":
                  system("clear")
                  password=input("Enter what you know of the password and what you don't as the @ symbol: ")
                  valores=input("Enter the data to be tested in the password: ")
                  longitud=input("Please enter the total length of the password: ")
                  system("clear")
                  print("Next, copy and paste the command that will be given to you into the console and run Hasher.py again.")
                  print(f"crunch {longitud} {longitud}  {valores} -t {password} -o ~/Hash_crack/wordlist.txt")
                  exit(2)
           else:
                 print("Invalid option!")
                 exit(2)


  def validation(self,password,hash_input,encryption):
      if encryption == hash_input:
               print("\n{***********************SUCCESS***********************}")
               print(f"[ ✔ ] Password Found:- {password}")
               exit(2)
      else:
           print(f"[*] Trying password:- {password}")




  def crack(self,hash_input,hash_verification):
    with open(self.rute_dictionary,'r',encoding='latin-1') as keywords_read:
        list_words=keywords_read.readlines()

    for keywords in set(list_words):
             password=keywords.strip()
             data=password.encode()
             if hash_verification == "md5":
               encryption=md5(password.encode('utf8')).hexdigest()
               self.validation(password,hash_input,encryption)
               
             elif hash_verification == "sha1":
               encryption=sha1(password.encode('utf8')).hexdigest()
               self.validation(password,hash_input,encryption)
               
             elif hash_verification == "sha224":
               encryption=sha224(password.encode('utf8')).hexdigest()
               encryption_sha3=sha3_224(password.encode('utf8')).hexdigest()
               self.validation(password,hash_input,encryption)
               if encryption_sha3 == hash_input:
                 print("\n{***********************SUCCESS***********************}")
                 print(f"[ ✔ ] Password Found:- {password}")
                 exit(2) 
               else:
                 print(f"[*] Trying password:- {password}")

             elif hash_verification == "sha384":
               encryption=sha384(password.encode('utf8')).hexdigest()
               encryption_sha3=sha3_384(password.encode('utf8')).hexdigest()
               self.validation(password,hash_input,encryption)
               if encryption_sha3 == hash_input:
                 print("\n{***********************SUCCESS***********************}")
                 print(f"[ ✔ ] Password Found:- {password}")
                 exit(2)
               else:
                 print(f"[*] Trying password:- {password}")

             elif hash_verification == "sha256":
               encryption=sha256(password.encode('utf8')).hexdigest()
               encryption_sha3=sha3_256(password.encode('utf8')).hexdigest()
               self.validation(password,hash_input,encryption)
               if encryption_sha3 == hash_input:
                 print("\n{***********************SUCCESS***********************}")
                 print(f"[ ✔ ] Password Found:- {password}")
                 exit(2)
               else:
                 print(f"[*] Trying password:- {password}")
               
               blas2=blake2s(data).hexdigest()
               if blas2 == hash_input:
                   print("\n{***********************SUCCESS***********************}")
                   print(f"[ ✔ ] Password Found:- {password}")
                   exit(2)
               else:
                   print(f"[*] Trying password:- {password}")

             elif hash_verification == "sha512":
               encryption=sha512(password.encode('utf8')).hexdigest()
               encryption_sha3=sha3_512(password.encode('utf8')).hexdigest()
               self.validation(password,hash_input,encryption)
               if encryption_sha3 == hash_input:
                  print("\n{***********************SUCCESS***********************}")
                  print(f"[ ✔ ] Password Found:- {password}")
                  exit(2) 
               else:
                  print(f"[*] Trying password:- {password}")

               blas2=blake2b(data).hexdigest() 
               if blas2 == hash_input: 
                    
                    print(f"[ ✔ ] Password Found:- {password}") 
                    exit(2) 
               else: 
                    print(f"[*] Trying password:- {password}")
                  
    print("[x] The password is not in the dictionary!")

         
  def show_help(self):
             print("""
Usage: 
     python3 Hasher.py
Help Menu:
     -h  --help  print the help menu
 ----------------------------
|  list of available hashes  |
 ----------------------------
|md5     |
|sha1    |
|sha224  |
|sha256  |
|sha384  |
|sha512  |
|sha3_256|
|sha3_224|
|sha3_384|
|sha3_512|
|blake2s |
|blake2b |
 --------
                    """)
    
    
  def main(self):
   try:
    if "-h" in argv or "--help" in argv:
               self.show_help()
               exit(2)
     
    self.banner()
    self.crunch()
    self.call_modules()
    hash_input=input("Enter the hash to decrypt: ")
    if len(hash_input) == self.md5:
             hash_verification="md5"
             system("clear")
             print("*****************************")
             print(" Wait, this may take a while ")
             print("*****************************")
             sleep(2)
             self.crack(hash_input,hash_verification)
    elif len(hash_input) == self.sha1:
             hash_verification="sha1"
             system("clear")
             print("*****************************")
             print(" Wait, this may take a while ")
             print("*****************************")
             sleep(2)
             self.crack(hash_input,hash_verification)
    elif len(hash_input) == self.sha224:
             hash_verification="sha224"
             system("clear")
             print("*****************************")
             print(" Wait, this may take a while ")
             print("*****************************")
             sleep(2)
             self.crack(hash_input,hash_verification)
    elif len(hash_input) == self.sha384:
             hash_verification="sha384"
             system("clear")
             print("*****************************")
             print(" Wait, this may take a while ")
             print("*****************************")
             sleep(2)
             self.crack(hash_input,hash_verification)
    elif len(hash_input) == self.sha256:
             hash_verification="sha256"
             system("clear")
             print("*****************************")
             print(" Wait, this may take a while ")
             print("*****************************")
             sleep(2)
             self.crack(hash_input,hash_verification)
    elif len(hash_input) == self.sha512:
             hash_verification="sha512"
             system("clear")
             print("*****************************")
             print(" Wait, this may take a while ")
             print("*****************************")
             sleep(2)
             self.crack(hash_input,hash_verification)
    else:
      self.show_help()
      
   except KeyboardInterrupt:
        print("BYE!!")

   except FileNotFoundError as e:
            print(f"Wordlist.txt does not exist in the path => {e}")
    
if __name__ == "__main__":
  crack=Hash_crack()
  crack.main()


__name__="Hasher"
__version__="1.0"
__license__="GPL"
__status__="alpha"
__author__="WhiteHack"
