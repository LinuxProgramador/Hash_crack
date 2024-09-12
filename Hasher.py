#!/usr/bin/python3

#Herramienta para romper hash por fuerza bruta en distros linux y termux

#La herramienta zcrack fue brindada por maquina1337 visita su pagina en github
#https://github.com/machine1337/zipcrack
#El banner fue brindado por CiKu370 visita su pagina en github
#https://github.com/CiKu370/hasher
#La herramienta RARNinja fue brindado por SHUR1K-N visita su pagina en github
#https://github.com/SHUR1K-N/RARNinja-RAR-Password-Cracking-Utility


from Crypto.Hash import RIPEMD160
from hashlib import md5,sha1,sha224,sha384,sha256,sha512,sha3_256,sha3_224,sha3_384,sha3_512,blake2s,blake2b
from sys import argv
from os import system,path,remove
from time import sleep
from getpass import getuser

class Hash_crack:


  def __init__(self):
    self.hash = {
    'sha1':sha1,
    'sha224':sha224,
    'sha384':sha384,
    'sha256':sha256,
    'sha512':sha512,
    'sha3_224':sha3_224,
    'sha3_384':sha3_384,
    'sha3_256':sha3_256,
    'sha3_512':sha3_512
    }
    self.md5=32
    self.sha1=40
    self.sha224=56
    self.sha256=64
    self.sha384=96
    self.sha512=128
    self.user=getuser()
    self.rute_dictionary_termux="/data/data/com.termux/files/home/Hash_crack/wordlist.txt"
    self.rute_dictionary_linux=f"/home/{self.user}/Hash_crack/wordlist.txt"
    self.os=path.exists("/data/data/com.termux/files/")
    
  def banner(self):
        print ('''\n
                 Hasher 1.0
  --------------------------------------------
 ' 88  88    db    .dP"Y8 88  88 88888 88""Yb '
 ' 88  88   dPYb   `Ybo." 88  88 88__  88__dP '
 ' 888888  dP__Yb  o.`Y8b 888888 88""  88"Yb  '
 ' 88  88 dP""""Yb 8bodP  88  88 88888 88  Yb '
 ' -------------------------------------------
               ''')
        

  def call_modules(self):
    confirm=input("Do you want to use (zcrack/rarninja/or \"no\" for none ): ").strip().lower()
    if confirm == "zcrack": 
      print("NOTE:This process may take time!") 
      sleep(3) 
      system("python3 ~/Hash_crack/zcrack.py")
      exit(2)       
    elif confirm == "rarninja":
      print("NOTE:This process may take time!") 
      sleep(3) 
      system("clear")
      system("python3 ~/Hash_crack/RARNinja.py")
      exit(2)  
      
      
  def user_os(self):
    return self.rute_dictionary_termux if self.os == True else self.rute_dictionary_linux
    
    
  def crunch(self):
     verificate=input("You want to use the existing dictionary (yes/no): ").strip().lower()
     if verificate == "no":
           remove(self.user_os())
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
                system("bash ~/Hash_crack/crunch.sh")
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


  def validation(self,many_hash,password,hash_input):
       if many_hash == hash_input:
            print("\n{***********************SUCCESS***********************}")
            print(f"[ ✔ ] Password Found:- {password}")
            exit(2)
       else:
            print(f"[*] Trying password:- {password}")
               
  def crack(self,hash_input,select):
     with open(self.user_os(),'r',encoding='latin-1') as keywords_read:
       for keywords in keywords_read:
             password=keywords.strip()
             data=password.encode()
             if select == None:
               encryption = md5(password.encode('latin-1')).hexdigest()
               self.validation(encryption,password,hash_input)
             elif select in self.hash:
               encryption = self.hash[select](password.encode('latin-1')).hexdigest()
               self.validation(encryption,password,hash_input)
             elif select == "rypemd-160":
                 RIPEMD = RIPEMD160.new()
                 RIPEMD.update(data)
                 if RIPEMD.hexdigest() == hash_input:
                    print("\n{***********************SUCCESS***********************}")
                    print(f"[ ✓ ] Password Found:- {password}")
                    exit(2)
                 else:
                    print(f"[*] Trying password:- {password}")
             elif select == "blake2s":
                blas2=blake2s(data).hexdigest()
                self.validation(blas2,password,hash_input)
             elif select == "blake2b":
                blas2=blake2b(data).hexdigest()
                self.validation(blas2,password,hash_input)
             else:
               print("Wrong name!")
               exit(2)
       print("[ X ] The password is not in the dictionary!")
                                    
  def show_help(self):
             print("Hasher 1.0. Tool for cracking multiple hashes.")
             print("""
Usage: 
     python3 Hasher.py
Help Menu:
     -h  --help  print the help menu
 ----------------------------
|   List of available hash   |
 ----------------------------
|md5       |
|sha1      |
|sha224    |
|sha256    |
|sha384    |
|sha512    |
|sha3_256  |
|sha3_224  |
|sha3_384  |
|sha3_512  |
|blake2s   |
|blake2b   |
|RIPEMD-160|
 ----------
                    """)
    
    
  def cracking_selection(self,hash_input,hash):
     if hash == 'md5':
        select = None
     else:
       select = input("Which one do you want to crack: ")
     sleep(1)
     system("clear")
     print("""
*****************************
Wait, this may take a while
*****************************
                   """)
     sleep(2)
     self.crack(hash_input,select)

  
  def main(self):
   try:
    hash = ''
    if "-h" in argv or "--help" in argv:
               self.show_help()
               exit(2)
    self.banner()
    self.crunch()
    self.call_modules()
    hash_input=input("Enter the hash to decrypt: ")
    if len(hash_input) == self.md5:
             hash = "md5"
             print("Type hash => md5")
             self.cracking_selection(hash_input,hash)
    elif len(hash_input) == self.sha1:
             print("Type hash => (sha1/rypemd-160)")
             self.cracking_selection(hash_input,hash)
    elif len(hash_input) == self.sha224:
             print("Type hash => (sha224/sha3_224)")   
             self.cracking_selection(hash_input,hash)
    elif len(hash_input) == self.sha384:
             print("Type hash => (sha384/sha3_384)")   
             self.cracking_selection(hash_input,hash)
    elif len(hash_input) == self.sha256:
             print("Type hash => (sha256/sha3_256/blake2s)")   
             self.cracking_selection(hash_input,hash)
    elif len(hash_input) == self.sha512:
             print("Type hash => (sha512/sha3_512/blake2b)")    
             self.cracking_selection(hash_input,hash)
    else:
        print()
        self.show_help()
      
   except KeyboardInterrupt:
        print("BYE!!")
   except FileNotFoundError as e:
        print(f"wordlist.txt does not exist in the path => {e}")
    
if __name__ == "__main__":
  crack=Hash_crack()
  crack.main()


__name__="Hasher"
__version__="1.0"
__license__="GPL"
__status__="Finished"
__author__="WhiteHack"
