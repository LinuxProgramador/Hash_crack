#!/usr/bin/python3

#Herramienta para romper hash por fuerza bruta en distros linux (Ubuntu/Debían) y termux


from Crypto.Hash import RIPEMD160
from hashlib import md5,sha1,sha224,sha384,sha256,sha512,sha3_256,sha3_224,sha3_384,sha3_512,blake2s,blake2b
from sys import argv,exit
from os import system,path,remove
from time import sleep
from getpass import getuser

class Hash_crack:
  '''
     Class called Hash_crack, which verifies that the type of hash entered is supported and proceeds to its decryption, in addition to calling the include third-party projects
  '''

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
    'sha3_512':sha3_512,
    'blake2b':blake2b,
    'blake2s':blake2s,
    'length_md5':32,
    'length_sha1':40,
    'length_sha224':56,
    'length_sha256':64,
    'length_sha384':96,
    'length_sha512':128,
    }
    self.user=getuser()
    self.rute_dictionary_termux="/data/data/com.termux/files/home/Hash_crack/wordlist.txt"
    self.rute_dictionary_linux=f"/home/{self.user}/Hash_crack/wordlist.txt"
    self.os=path.exists("/data/data/com.termux/files/")
    
  def banner(self):
        '''
           Method where the baneer is established
        '''
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
    '''
       Call for third-party projects included to extend the program's functionality 
    '''
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
    '''
       Detects the operating system and in relation to that returns the path of the dictionary 
    '''
    return self.rute_dictionary_termux if self.os == True else self.rute_dictionary_linux
    
    
  def crunch_0(self):
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
    

  def crunch2(sel):
     system("clear")
     minimo=input("Enter the minimum password: ")
     maximo=input("Enter the maximum password: ")
     valores=input("Enter the data to generate the dictionary: ")
     system("clear")
     print("Then copy and paste the command that will be given to you into the console and run Hasher.py again.")
     print(f"crunch {minimo} {maximo} {valores} -o ~/Hash_crack/wordlist.txt")
     exit(2)


  def crunch3(self):
    system("clear")
    password=input("Enter what you know of the password and what you don't as the @ symbol: ")
    valores=input("Enter the data to be tested in the password: ")
    longitud=input("Please enter the total length of the password: ")
    system("clear")
    print("Next, copy and paste the command that will be given to you into the console and run Hasher.py again.")
    print(f"crunch {longitud} {longitud}  {valores} -t {password} -o ~/Hash_crack/wordlist.txt")
    exit(2)

  
  def crunch(self):
     '''
        Generate custom dictionaries
     '''
     verificate=input("You want to use the existing dictionary (yes/no): ").strip().lower()
     if verificate == "no":
           remove(self.user_os())
           self.crunch_0()
           comand=input("option: ")
           if comand == "1":
                system("bash ~/Hash_crack/crunch.sh")
                exit(2)
           elif comand == "2":
                 self.crunch2()                  
           elif comand == "3":
                 self.crunch3()               
           else:
                 print("Invalid option!")
                 exit(2)


  
  def duration(self):
     '''
        Method that calculates the approximate duration of the crack based on the size of the dictionary
     '''

     #Note: calculations may not be as accurate
     sizes_mb = path.getsize(self.user_os()) / (1024 ** 2)
      
     if sizes_mb > 1.0 and sizes_mb <= 20.0:
            return "~2 mins"
     elif sizes_mb > 20.0 and sizes_mb <= 40.0:
            return "~6 mins"
     elif sizes_mb > 40.0 and sizes_mb <= 81.0:
            return "~10 mins"
     elif sizes_mb > 81.0 and sizes_mb <= 140.0:
            return "~18 mins"
     elif sizes_mb > 140.0 and sizes_mb <= 250.0:
            return "~32 mins"
     elif sizes_mb > 250.0 and sizes_mb <= 600.0:
            return "~1 and 19 mins"
     elif sizes_mb > 600.0:
            return "more 2 hours"

  

  def validation(self,many_hash,password,hash_input,x):
       '''
          Validates if the hash is equal to the encrypted password
       '''
       if many_hash == hash_input:
            print("\n{***********************SUCCESS***********************}")
            print(f"[ ✔ ] Password Found:- {password}")
            exit(2)
       else:
            print(f"[{x}] Trying password:- {password}")
               
  def crack(self,hash_input,select):
     '''
        Encode each word in the dictionary, to verify with the hash of the key
     '''
     x = self.duration()
     with open(self.user_os(),'r',encoding='latin-1') as keywords_read:
       for keywords in keywords_read:
             password=keywords.strip()
             data=password.encode()
             if select == None:
               encryption = md5(password.encode('latin-1')).hexdigest()
               self.validation(encryption,password,hash_input,x)
             elif select in self.hash:
               encryption = self.hash[select](password.encode('latin-1')).hexdigest()
               self.validation(encryption,password,hash_input,x)
             elif select == "rypemd-160":
                 RIPEMD = RIPEMD160.new()
                 RIPEMD.update(data)
                 if RIPEMD.hexdigest() == hash_input:
                    print("\n{***********************SUCCESS***********************}")
                    print(f"[ ✓ ] Password Found:- {password}")
                    exit(2)
                 else:
                    print(f"[{x}] Trying password:- {password}")
             elif select in self.hash:
                blas2=self.hash[select](data).hexdigest()
                self.validation(blas2,password,hash_input,x)        
             else:
               print("Wrong name!")
               exit(2)
       print("[ X ] The password is not in the dictionary!")
                                    
  def show_help(self):
             '''
                Method that displays a help menu 
             '''
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
     '''
        Allows the user to choose which hash to crack
     '''
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
   '''
      Performs tasks based on what the user selects 
   '''
   try:
    hash = ''
    if "-h" in argv or "--help" in argv:
               self.show_help()
               exit(2)
    self.banner()
    self.crunch()
    self.call_modules()
    hash_input=input("Enter the hash to decrypt: ")
    if len(hash_input) == self.hash['length_md5']:
             hash = "md5"
             print("Type hash => md5")
             self.cracking_selection(hash_input,hash)
    elif len(hash_input) == self.hash['length_sha1']:
             print("Type hash => (sha1/rypemd-160)")
             self.cracking_selection(hash_input,hash)
    elif len(hash_input) == self.hash['length_sha224']:
             print("Type hash => (sha224/sha3_224)")   
             self.cracking_selection(hash_input,hash)
    elif len(hash_input) == self.hash['length_sha384']:
             print("Type hash => (sha384/sha3_384)")   
             self.cracking_selection(hash_input,hash)
    elif len(hash_input) == self.hash['length_sha256']:
             print("Type hash => (sha256/sha3_256/blake2s)")   
             self.cracking_selection(hash_input,hash)
    elif len(hash_input) == self.hash['length_sha512']:
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
__author__="JP Rojas"
