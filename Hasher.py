#!/usr/bin/python3

#Herramienta para romper hashes por fuerza bruta en termux

#La herramienta zcrack fue brindada por maquina1337 visita su pagina en github
#https://github.com/machine1337/zipcrack
#El banner fue brindado por CiKu370 visita su pagina en github
#https://github.com/CiKu370/hasher
#La herramienta RARNinja fue brindado por SHUR1K-N visita su pagina en github
#https://github.com/SHUR1K-N/RARNinja-RAR-Password-Cracking-Utility



from hashlib import md5,sha1,sha224,sha384,sha256,sha512,sha3_256,sha3_224,sha3_384,sha3_512,blake2s
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

    confirm=input("Do you want to use (zcrack/RARNinja): ").strip().lower()
    if confirm == "zcrack": 
      print("NOTE:This process may take time!") 
      sleep(3) 
      system("python3 /data/data/com.termux/files/home/Hash_crack/zcrack.py")
             
    elif confirm == "rarninja":
      print("NOTE:This process may take time!") 
      sleep(3) 
      system("python3 /data/data/com.termux/files/home/Hash_crack/RARNinja.py")
             
    
      


  def crunch(self):

     verificate=input("You want to use the existing dictionary (yes/no): ").strip().lower()
     if verificate == "no":
           system("rm -f /data/data/com.termux/files/home/Hash_crack/wordlist.txt")
           print("We'll use Crunch to generate a new dictionary!")
           sleep(3)
           system("clear")
           print("""
1) crear diccionario concatenando palabras por ejemplo:
   sin concatenar (Harry  Hermallony  Ron)
   con concatenar (HarryHermallonyRon)



2) crear diccionario especificando un minimo y un maximo
   de caracteres a utilizar por ejemplo: (crunch 4 8 abcdef)

   ¡Aqui me generara un minimo de 4 y un maximo de 8
   caracteres usando todas las combinaciones posibles
   de la abcdef o cualquier otro dato que se le asigne.!




3) crear un diccionario con la inicial de una contraseña
   y el resto probando combinaciones por ejemplo:
   qwerty (12345)



NOTA:Tener cuidado con la cantidad de contraseñas que
     se pueden generar, puede llegar hasta gigas y bloquear
     el telefono.
                  """)
           comand=input("opcion: ")
           if comand == "1":
                system("bash /data/data/com.termux/files/home/Hash_crack/crunch.sh")

           elif comand == "2":
                   system("clear")
                   minimo=input("ingrese el minimo de la contrasena: ")
                   maximo=input("ingrese el maximo de la contraseña: ")
                   valores=input("ingrese los datos a generar el diccionario: ")
                   system("clear")
                   print("A continuacion copie y pegue en la consola ese comando que se le dara y vuelva a ejecutar Hasher.py")
                   print(f"crunch {minimo} {maximo} {valores} -o ~/Hash_crack/wordlist.txt")
                   


           elif comand == "3":
                  system("clear")
                  password=input("ingrese lo que conoce de la contraseña y lo que no como simbolo @: ")
                  valores=input("ingrese los datos a probar en la contraseña: ")
                  longitud=input("ingrese la longitud total de la contraseña: ")
                  system("clear")
                  print("A continuacion copie y pegue en la consola ese comando que se le dara y vuelva a ejecutar Hasher.py")
                  print(f"crunch {longitud} {longitud}  {valores} -t {password} -o ~/Hash_crack/wordlist.txt")
                  

           else:
                 print("¡Opcion no valida!")
                





  def validation(self,password,hash_input,encryption):

      if encryption == hash_input:
               print(f"su contraseña es {password}")
               exit(2)
        




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
                 print(f"su contraseña es {password}")
                 exit(2) 
                


             elif hash_verification == "sha384":
               encryption=sha384(password.encode('utf8')).hexdigest()
               encryption_sha3=sha3_384(password.encode('utf8')).hexdigest()
               self.validation(password,hash_input,encryption)
               if encryption_sha3 == hash_input:
                 print(f"su contraseña es {password}")
                 exit(2)



             elif hash_verification == "sha256":
               encryption=sha256(password.encode('utf8')).hexdigest()
               encryption_sha3=sha3_256(password.encode('utf8')).hexdigest()
               self.validation(password,hash_input,encryption)
               if encryption_sha3 == hash_input:
                 print(f"su contraseña es {password}")
                 exit(2)

               else:
                 blas2=blake2s(data).hexdigest()
                 if blas2 == hash_input:
                     print(f"su contraseña es {password}")
                     exit(2)
               


             elif hash_verification == "sha512":
               encryption=sha512(password.encode('utf8')).hexdigest()
               encryption_sha3=sha3_512(password.encode('utf8')).hexdigest()
               self.validation(password,hash_input,encryption)
               if encryption_sha3 == hash_input:
                  print(f"su contraseña es {password}")
                  exit(2) 
                  
    print("¡La contraseña no esta en el diccionario!")

         
       
    
   

    

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
    hash_input=input("ingrese el hash a decifrar: ")
    if len(hash_input) == self.md5:
             hash_verification="md5"
             system("clear")
             sleep(1)
             print("espera esto puede tardar un poco")
             self.crack(hash_input,hash_verification)

    elif len(hash_input) == self.sha1:
             hash_verification="sha1"
             system("clear")
             sleep(1)
             print("espera esto puede tardar un poco")
             self.crack(hash_input,hash_verification)

    elif len(hash_input) == self.sha224:
             hash_verification="sha224"
             system("clear")
             sleep(1)
             print("espera esto puede tardar un poco")
             self.crack(hash_input,hash_verification)

    elif len(hash_input) == self.sha384:
             hash_verification="sha384"
             system("clear")
             sleep(1)
             print("espera esto puede tardar un poco")
             self.crack(hash_input,hash_verification)

    elif len(hash_input) == self.sha256:
             hash_verification="sha256"
             system("clear")
             sleep(1)
             print("espera esto puede tardar un poco")
             self.crack(hash_input,hash_verification)

    elif len(hash_input) == self.sha512:
             hash_verification="sha512"
             system("clear")
             sleep(1)
             print("espera esto puede tardar un poco")
             self.crack(hash_input,hash_verification)


    else:
      self.show_help()
      

   except KeyboardInterrupt:
        print("BYE!!")
    

if __name__ == "__main__":
  crack=Hash_crack()
  crack.main()




__name__="Hasher"
__version__="1.0"
__license__="GPL"
__status__="alpha"
__author__="WhiteHack"
