#!/usr/bin/python3

#Herramienta para romper hash por fuerza bruta en distros linux (Ubuntu/Debían) y termux


from Crypto.Hash import RIPEMD160
from hashlib import md5,sha1,sha224,sha384,sha256,sha512,sha3_256,sha3_224,sha3_384,sha3_512,blake2s,blake2b,shake_128,shake_256
from sys import argv,exit
from os import system,path,remove
from time import sleep
from getpass import getuser
from passlib.hash import sha256_crypt,sha512_crypt

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
    'sha256crypt':sha256_crypt,
    'sha512crypt':sha512_crypt,
    'length_bcrypt':60,
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

  def auxiliary_crack(self,password):
    '''
     Helper function that will show the correct key
    '''
    print("\n{***********************SUCCESS***********************}")
    print(f"[ ✓ ] Password Found:- {password}")
    exit(2)



  def shacrypt(self,hash_input,password,select):
        '''
        function that separates the logic of the sha256crypt and sha512crypt hash so that it does not give an error with blake2
        '''
        if self.hash[select].verify(password, hash_input):
          self.auxiliary_crack(password)
        else:
          print(f"[indefinite] Trying password:- {password}")

  
  def crack(self,hash_input,select):
     '''
        Encode each word in the dictionary, to verify with the hash of the key
     '''
     x = self.duration()
     with open(self.user_os(),'r',encoding='latin-1') as keywords_read:
       for keywords in keywords_read:
             password=keywords.strip()
             data=password.encode()
             #md5 hash check
             if select == "md5":
               encryption = md5(password.encode('latin-1')).hexdigest()
               self.validation(encryption,password,hash_input,x)

             #Checking hash shakes
             elif select == "shake-256":
                hash1 = shake_256(data).hexdigest(int(len(hash_input)/2))
                if hash1 == hash_input:
                    self.auxiliary_crack(password)
                else:
                    print(f"[{x}] Trying password:- {password}")

         
             elif select == "shake-128":
                 shake = shake_128()
                 shake.update(data)
                 calculated_hash = shake.digest(len(bytes.fromhex(hash_input))).hex()
                 if calculated_hash == hash_input:
                    self.auxiliary_crack(password)
                 else:
                    print(f"[{x}] Trying password:- {password}")

             #checking shacrypt hashes
             elif select == "sha256crypt" or select == "sha512crypt":
                  self.shacrypt(hash_input,password,select)

             #bcrypt hash check 
             elif select == "bcrypt":
                if not self.os:
                   from bcrypt import checkpw
                   if checkpw(data, bytes(hash_input,encoding="latin-1")):
                     self.auxiliary_crack(password)
                   else:
                     print(f"[indefinite] Trying password:- {password}")
                else:
                    print("""
bcrypt is not compatible with termux:
option 1: install \"userland\" from play store
option 2: install \"hash suite droid\" from this link: https://apkpure.com/en/hash-suite-droid/com.hashsuite.droid
                          """)
                    exit(2)

             #checking  sha1, sha2, sha3 hashes
             elif select in self.hash:
               encryption = self.hash[select](password.encode('latin-1')).hexdigest()
               self.validation(encryption,password,hash_input,x)

             #rypemd-160 hash check
             elif select == "rypemd-160":
                 RIPEMD = RIPEMD160.new()
                 RIPEMD.update(data)
                 if RIPEMD.hexdigest() == hash_input:
                    self.auxiliary_crack(password)
                 else:
                    print(f"[{x}] Trying password:- {password}")

             #Checking blake2 hashes
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
     python3 Hasher.py -sk  parameter to enter the shake-128 hash
     python3 Hasher.py -sk2  parameter to enter the shake-256 hash
Help Menu:
     -h  --help  print the help menu
 ----------------------------
|   List of available hash   |
 ----------------------------
|md5        |
|sha1       |
|sha224     |
|sha256     |
|sha384     |
|sha512     |
|sha3_256   |
|sha3_224   |
|sha3_384   |
|sha3_512   |
|blake2s    |
|blake2b    |
|RIPEMD-160 |
|bcrypt     |
|sha256crypt|
|sha512crypt|
|shake-128  |
|shake-256  |
 ----------
                    """)
    
    
  def cracking_selection(self,hash_input,hash):
     '''
        Allows the user to choose which hash to crack
     '''
     if hash == "md5":
        select = hash
     elif hash == "shake-128":
        select = hash
     elif hash == "shake-256":
        select = hash
     elif hash == "sha256crypt":
        select = hash
     elif hash == "sha512crypt":
        select = hash
     elif hash == "bcrypt":
        select = hash
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

  def hash_secure_info(self,hash_input,hash):  
       '''
       reports that a secure hash is being cracked 
       '''
       print(f"Type hash => {hash}")
       print(f"{hash.capitalize()} is considered a secure hash, it is recommended to use small dictionaries")
       sleep(4)
       self.cracking_selection(hash_input,hash)
    

  def auxiliary_main(self,hash_input,hash):
     '''
     Helper function to validation shake hash
     '''
     if hash_input:
       if len(hash_input) >= 1 and len(hash_input) <= 2056:
         self.cracking_selection(hash_input,hash)
         exit(2)
       else:
         print("exceeded the allowed bits of \"1024\"")
         exit(2)
     else:
         print()
         self.show_help()
         exit(2)
       
    
  def main(self):
   '''
      Performs tasks based on what the user selects 
   '''
   try:
    hash = ''
    if "-h" in argv or "--help" in argv:
               self.show_help()
               exit(2)
    if "-sk" in argv:
         hash_input=input("Enter the hash shake-128: ")
         hash = "shake-128"
         self.auxiliary_main(hash_input,hash)
    elif "-sk2" in argv:
         hash_input=input("Enter the hash shake-256: ")
         if not hash_input.isalnum():
             if hash_input:
               print("You did not enter a valid hash!")
               exit(2)
         hash = "shake-256"
         self.auxiliary_main(hash_input,hash)
    self.banner()
    self.crunch()
    self.call_modules()
    hash_input=input("Enter the hash to decrypt: ")
    if len(hash_input) == self.hash['length_md5']:
             hash = "md5"
             print(f"Type hash => {hash}")
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
    elif len(hash_input) == self.hash['length_bcrypt'] and any(v in hash_input[0:5] for v in ["2a$", "2b$", "2y$"]):
             hash = "bcrypt"
             self.hash_secure_info(hash_input,hash)
    elif "$5" in hash_input[0:2]:
             hash = "sha256crypt"
             self.hash_secure_info(hash_input,hash)
    elif "$6" in hash_input[0:2]:
             hash = "sha512crypt"
             self.hash_secure_info(hash_input,hash)
    else:
        if hash_input:
          print("""\n
 \"The hash entered is of incorrect length or does not comply
 with the standards supported by the script.
 Please verify and try again.\"
                """)
        print()
        self.show_help()
      
   except KeyboardInterrupt:
        print("BYE!!")
   except FileNotFoundError as e:
        print(f"wordlist.txt does not exist in the path => {e}")
   except ValueError:
       print("You did not enter a valid hash!")
    
if __name__ == "__main__":
  crack=Hash_crack()
  crack.main()


__name__="Hasher"
__version__="1.0"
__license__="GPL"
__status__="Finished"
__author__="JP Rojas"
