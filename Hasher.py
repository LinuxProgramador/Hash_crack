#!/usr/bin/python3

#Tool to crack hashes by brute force on linux distros (Ubuntu/Debian) and termux


from Crypto.Hash import RIPEMD160,MD4
from hashlib import md5,sha1,sha224,sha384,sha256,sha512,sha3_256,sha3_224,sha3_384,sha3_512,blake2s,blake2b,shake_128,shake_256,pbkdf2_hmac,algorithms_available,new
from sys import argv,exit
from os import system,path,remove
from time import sleep
from getpass import getuser
from passlib.hash import sha256_crypt,sha512_crypt,md5_crypt,apr_md5_crypt,msdcc2,phpass
from bcrypt import checkpw
from base64 import b64decode
from json import loads
from gmssl import sm3,func
from random import choice
from whirlpool import new as wpl

class Hash_crack:
  '''  Class called Hash_crack, which verifies that the type of hash entered is supported and proceeds to its decryption, in addition to calling the include third-party projects '''

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
    'md5crypt':md5_crypt,
    'apr1':apr_md5_crypt,
    'DCC2':msdcc2,
    'phpass':phpass,
    'length_bcrypt':60,
    'length_md5':32,
    'length_sha1':40,
    'length_sha224':56,
    'length_sha256':64,
    'length_sha384':96,
    'length_sha512':128,
    }
    self.modules_names = {
"1":"zcrack.py",
"2":"RARNinja.py"
    }
    self.modules_multiprocess = {
"1":"multiprocess1.py",
"2":"multiprocess2.py"
    }
    self.user=getuser()
    self.termux_dict_path="/data/data/com.termux/files/home/Hash_crack/wordlist.txt"
    self.linux_dict_path=f"/home/{self.user}/Hash_crack/wordlist.txt"
    self.is_termux=path.exists("/data/data/com.termux/files/")
    self.previous_password = ''
    self.previous_password_bin = b''
    self.attempt_count = 0


  def get_encoder(self):
    ''' The user is asked to choose a text encoder '''
    encoder = ''
    if not any( help in argv for help in ["-h","--help","-ct7"]):
      print("INFO: For compatibility reasons with certain symbols, Do you choose encoder:")
      print("1) latin-1\n2) utf-8")
      encoder_text = input("option: ").strip()
      encoder = "latin-1" if encoder_text == "1" else "utf-8"
      sleep(1)
      system("clear")
    return encoder

  def banner(self):
        '''  Method where the baneer is established '''
        print ('''\n
                 Hasher 1.0
  --------------------------------------------
 ' 88  88    db    .dP"Y8 88  88 88888 88""Yb '
 ' 88  88   dPYb   `Ybo." 88  88 88__  88__dP '
 ' 888888  dP__Yb  o.`Y8b 888888 88""  88"Yb  '
 ' 88  88 dP""""Yb 8bodP  88  88 88888 88  Yb '
 ' -------------------------------------------
               ''')
        print("INFO: Tool for cracking multiple types of hashes")
        print("INFO: Use the help menu for guidance: 'python3 Hasher.py -h'\n")
        return


  def call_modules(self):
    '''  Call for third-party projects included to extend the program's functionality '''
    print("You want to use:")
    print("1) zcrack: Crack the password of a ZIP file.\n2) rarninja: Crack the password of a RAR file.\n3) multiprocess: Parallel decryption of a hash using four dictionaries.\n4) bruteforce: Brute force attack without dictionary.\n5) ssh: Brute force to SSH service\n6) for \"none\"")
    option_chosen = input("option: ").strip()
    if option_chosen in self.modules_names:
      print("INFO:This process may take time!")
      sleep(3)
      system("clear")
      system(f"python3 ~/Hash_crack/{self.modules_names[option_chosen]}")
      exit(2)
    elif option_chosen == "3":
      for _ in range(2):
       print("""
INFO: This method is ideal for very large dictionaries or testing four dictionaries simultaneously, as it increases the probability of successfully decrypting a hash.
INFO: Use the following command to split a large dictionary into 100 MB chunks on Linux or Termux:
split -b 100M rockyou.txt

Options:
1) Use this option for fast hashes such as sha512sum, sha256sum, whirlpool, sha512-256, sm3, ssha, mysql 5.X, md5, NTLM, sha1, sha2, sha3, blake2, shake or ripemd-160.
2) Use this option for slow hashes such as phpass, bcrypt, DCC2, apr1, md5crypt, shacrypt or wpa-psk.

WARNING: On 4-core only systems, may slow down your computer
INFO: To optimize decryption speed, split multiprocessing into two sections. This only applies to systems with eight or more cores; enabling the CPU thermal throttling lock is recommended.
Additional INFO: Method 2 may take significantly longer due to the security measures of these hashing algorithms.
""")
       option_chosen_2 = input("option: ").strip()
       if not option_chosen_2 in ["1","2"]:
         self.attempt_count += 1
         if self.attempt_count == 1:
            print("Incorrect choice, please try again")
         sleep(2)
         system("clear")
       elif option_chosen_2 in self.modules_multiprocess:
         system("clear")
         system(f"python3 ~/Hash_crack/{self.modules_multiprocess[option_chosen_2]}")
         exit(2)
    elif option_chosen == "4":
         print("Recommendation: Split the brute force module into two sections to optimize hash cracking efficiency (it is recommended to limit it to two sections).")
         sleep(6)
         system("clear")
         system("python3 ~/Hash_crack/brute_force.py")
         exit(2)
    elif option_chosen == "5":
         if not self.is_termux:
           system("clear")
           system("bash ~/Hash_crack/start_tor.sh")
           sleep(1)
           system("proxychains4 python3 ~/Hash_crack/ssh_service_attack.py")
           system("pkill tor")
           exit(2)
         else:
           print("Not supported on Termux")
           exit(2)
    return


  def directory_path(self):
    '''   Detects the operating system and in relation to that returns the path of the dictionary  '''
    return self.termux_dict_path if self.is_termux == True else self.linux_dict_path


  def crunch_info(self):
    print("We'll use Crunch to generate a new dictionary!")
    sleep(3)
    system("clear")
    print("""
1) create dictionary by concatenating words for example:
   unconcatenated (Harry Hermallony Ron) with concatenate (HarryHermallonyRon)
   taking into account that it generates all possible combinations of these.

2) create dictionary specifying a minimum and maximum of characters to use for example:
   (crunch 4 8 abcdef) Here it will generate a minimum of 4 and a maximum of 8 characters using all possible combinations of the \"abcdef\" or any other data assigned to it.!

3) create a dictionary with the initial of a password and the rest trying combinations for example:
   qwerty (12345)
   INFO: It is important to emphasize that if the password is hello123 and the initials that you do not know are 123, then put them in @ for example hello@@@ and the exact length for example in this case would be 8
   INFO: the \"@\" can go in any position of the key, it is only used to specify where the combinations given by the user will be tested.

WARNING:BE CAREFUL WITH THE NUMBER OF PASSWORDS YOU USE. CAN BE GENERATED, IT CAN REACH UP TO GIGABYTES AND BLOCK THE SYSTEM!!!!!!!
                  """)
    return

  def crunch_option2(sel):
     system("clear")
     minimum = input("Enter the minimum password: ").strip()
     maximum = input("Enter the maximum password: ").strip()
     values = input("Enter the data to generate the dictionary: ").strip()
     system("clear")
     print("Then copy and paste the command that will be given to you into the console and run Hasher.py again:")
     print(f"crunch {minimum} {maximum} {values} -o ~/Hash_crack/wordlist.txt")
     exit(2)


  def crunch_option3(self):
    system("clear")
    password = input("Enter what you know of the password and what you don't as the @ symbol: ").strip()
    values = input("Enter the data to be tested in the password: ").strip()
    length = input("Please enter the total length of the password: ").strip()
    system("clear")
    print("Next, copy and paste the command that will be given to you into the console and run Hasher.py again:")
    print(f"crunch {length} {length}  {values} -t {password} -o ~/Hash_crack/wordlist.txt")
    exit(2)


  def crunch(self):
     '''  Generate custom dictionaries '''
     confirmation = input("You want to use the existing dictionary (y/n): ").strip().lower()
     if confirmation == "n":
           remove(self.directory_path())
           self.crunch_info()
           option_chosen = input("option: ").strip()
           if option_chosen == "1":
                system("bash ~/Hash_crack/crunch.sh")
                exit(2)
           elif option_chosen == "2":
                 self.crunch_option2()
           elif option_chosen == "3":
                 self.crunch_option3()
           else:
                 print("Invalid option!")
                 exit(2)
     return

  def approximate_duration(self):
     '''  Method that calculates the approximate duration of the crack based on the size of the dictionary '''
     #Note: calculations may not be as accurate
     #Rather, what is calculated is the approximate time.
     sizes_mb = path.getsize(self.directory_path()) / (1024 ** 2)
     ranges = {
        (1.0, 20.0): "~2 mins",
        (20.0, 40.0): "~6 mins",
        (40.0, 81.0): "~10 mins",
        (81.0, 140.0): "~18 mins",
        (140.0, 250.0): "~32 mins",
        (250.0, 600.0): "~1 and 19 mins",
        (600.0, float('inf')): "more 2 hours"
     }
     for size_range, duration in ranges.items():
        if size_range[0] <= sizes_mb < size_range[1]:
            return duration

     return "~30 seconds"


  def get_cracking_parameters(self):
      '''  Asks the user if he wants to apply a combo attack or
      if he wants to execute the fast cracking mode  '''
      #Note: not all possible combinations are tested to avoid blocking the script or extending the
      #timeout too much, as there would be many millions of possible combinations.
      print("You want to do a combo attack: \"mixing the keys\" (y/n): ",end="")
      combined = input().strip().lower()
      is_fast_mode = input("Do you want to use the fast crack version (y/n): ").strip().lower()
      wait_time = input("Do you want to prevent overheating the processor? (y/n): ").strip().lower()
      #Basic rules such as uppercase and lowercase are applied to increase the probability of finding the correct password.
      print("Rules:\n1) Use numbers\n2) Use uppercase letters\n3) Use lowercase letters\n4) Use symbols\n5) Use capital letters only on the first letter\n6) Use character substitution: example (S -> $)\n7) for \"none\"")
      print("INFO: unsupported combinations (14/23/35/25)")
      self.rules = input("option: ").strip().replace(" ", "")
      return combined,is_fast_mode,wait_time



  def rules_parameters(self,wpa_psk,password,data,crackTimeEstimate):
    ''' Changes passwords by adding a random number or symbol and changing case according to self.rules, unless the hash key setting is enabled '''
    numbers = ["1234","123456789","12345","123456","12345678"]
    symbols = ["#","!","$","%","@","&"]
    character_substitution = {"a":"@","A":"4","e":"3","E":"3","i":"1","I":"1","o":"0","O":"0","s":"$","S":"5","t":"7","T":"7","ó":"0","Ó":"0","á":"@","Á":"4","é":"3","É":"3","í":"1","Í":"1"}
    chosen_rules = self.rules if self.rules in ['1','2','3','4','5','12','13','15','21','31','51','42','24','34','43','54','45','6','64','46','61','16','56','65','26','62','36','63'] else ''
    if chosen_rules:
        crackTimeEstimate = 'time unknown'
        if chosen_rules in ['1']:
              password += choice(numbers)
              if not wpa_psk:
                 data += bytes(choice(numbers), encoding=self.encoder)
        elif chosen_rules in ['4']:
              password += choice(symbols)
              if not wpa_psk:
                 data += bytes(choice(symbols), encoding=self.encoder)
        elif chosen_rules in ['3']:
              password = password.lower()
              if not wpa_psk:
                 data = data.lower()
        elif chosen_rules in ['2']:
              password = password.upper()
              if not wpa_psk:
                 data = data.upper()
        elif chosen_rules in ['5']:
              password = password.capitalize()
              if not wpa_psk:
                 data = data.capitalize()
        elif chosen_rules in ['6']:
               for char in character_substitution:
                  password = password.replace(char,character_substitution[char])
                  if not wpa_psk:
                     data = data.replace(bytes(char,encoding=self.encoder),bytes(character_substitution[char],encoding=self.encoder))
        elif chosen_rules in ['64','46']:
               for char in character_substitution:
                  password = password.replace(char,character_substitution[char])
                  if not wpa_psk:
                     data = data.replace(bytes(char,encoding=self.encoder),bytes(character_substitution[char],encoding=self.encoder))
               password += choice(symbols)
               if not wpa_psk:
                 data += bytes(choice(symbols), encoding=self.encoder)
        elif chosen_rules in ['61','16']:
               for char in character_substitution:
                  password = password.replace(char,character_substitution[char])
                  if not wpa_psk:
                     data = data.replace(bytes(char,encoding=self.encoder),bytes(character_substitution[char],encoding=self.encoder))
               password += choice(numbers)
               if not wpa_psk:
                 data += bytes(choice(numbers), encoding=self.encoder)
        elif chosen_rules in ['56','65']:
               for char in character_substitution:
                  password = password.replace(char,character_substitution[char])
                  if not wpa_psk:
                     data = data.replace(bytes(char,encoding=self.encoder),bytes(character_substitution[char],encoding=self.encoder))
               password = password.capitalize()
               if not wpa_psk:
                 data = data.capitalize()
        elif chosen_rules in ['26','62']:
              for char in character_substitution:
                  password = password.replace(char,character_substitution[char])
                  if not wpa_psk:
                     data = data.replace(bytes(char,encoding=self.encoder),bytes(character_substitution[char],encoding=self.encoder))
              password = password.upper()
              if not wpa_psk:
                 data = data.upper()
        elif chosen_rules in ['36','63']:
              for char in character_substitution:
                  password = password.replace(char,character_substitution[char])
                  if not wpa_psk:
                     data = data.replace(bytes(char,encoding=self.encoder),bytes(character_substitution[char],encoding=self.encoder))
              password = password.lower()
              if not wpa_psk:
                 data = data.lower()
        elif chosen_rules in ['12','21']:
              password += choice(numbers)
              password = password.upper()
              if not wpa_psk:
                 data += bytes(choice(numbers), encoding=self.encoder)
                 data = data.upper()
        elif chosen_rules in ['13','31']:
              password += choice(numbers)
              password = password.lower()
              if not wpa_psk:
                 data += bytes(choice(numbers), encoding=self.encoder)
                 data = data.lower()
        elif chosen_rules in ['15','51']:
              password += choice(numbers)
              password = password.capitalize()
              if not wpa_psk:
                 data += bytes(choice(numbers), encoding=self.encoder)
                 data = data.capitalize()
        elif chosen_rules in ['42','24']:
              password += choice(symbols)
              password = password.upper()
              if not wpa_psk:
                 data += bytes(choice(symbols), encoding=self.encoder)
                 data = data.upper()
        elif chosen_rules in ['34','43']:
              password += choice(symbols)
              password = password.lower()
              if not wpa_psk:
                 data += bytes(choice(symbols), encoding=self.encoder)
                 data = data.lower()
        elif chosen_rules in ['54','45']:
              password += choice(symbols)
              password = password.capitalize()
              if not wpa_psk:
                 data += bytes(choice(symbols), encoding=self.encoder)
                 data = data.capitalize()
    return password,data,crackTimeEstimate


  def faster(self,is_fast_mode,crackTimeEstimate,password):
      '''  Function that will not print attempts if the user wants a quick crack '''
      if is_fast_mode != "y":
          print(f"[{crackTimeEstimate}] Trying password:- {password.strip()}")


  def auxiliary_crack(self,password,wpa_psk,ssid):
   ''' Helper function that will show the correct key '''
   print("\n{***********************SUCCESS***********************}")
   if wpa_psk:
     print(f"[✓] SSID: {ssid}")
   print(f"[✓] Password Found:- {password.strip()}")
   exit(2)


  def validation(self,many_hash,hash_input,password,wpa_psk,ssid,is_fast_mode,crackTimeEstimate):
       '''Validates if the hash is equal to the password'''
       if many_hash.lower() == hash_input.lower():
            self.auxiliary_crack(password,wpa_psk,ssid)
       else:
            self.faster(is_fast_mode,crackTimeEstimate,password)

  def validation_combined(self,password,data,keyclean,keyBin,wpa_psk):
      '''Function that combines keys if the value of the variable combined is "y"'''
      if self.attempt_count % 2 == 0:
         password += self.previous_password
         if not wpa_psk:
            data +=  self.previous_password_bin
      else:
         password = self.previous_password + password
         if not wpa_psk:
            data = self.previous_password_bin + data
      self.previous_password = keyclean
      if not wpa_psk:
         self.previous_password_bin = keyBin
      self.attempt_count += 1
      return password,data


  def validate_and_transform_entry(self,password_list):
     ''' Validates if the input is a string and not a list. If it is, transforms the value to "1"'''
     validation_str = type(password_list) is str
     if validation_str:
            password_list = "1"
     return validation_str,password_list


  def hash_cracking_worker(self,password_list,crackTimeEstimate,is_fast_mode,ssid,wpa_psk,hash_input,select,combined):
      '''  Processes an input and validates passwords against various hash algorithms. '''
      backup_password_list = password_list if type(password_list) is str else ''
      validation_str,password_list = self.validate_and_transform_entry(password_list)
      for keywords in password_list:
          if validation_str:
              keyclean = backup_password_list.strip()
          else:
              keyclean = keywords
          password = keyclean
          keyBin = password.encode(self.encoder)
          data = keyBin

          if combined == "y":
             password,data = self.validation_combined(password,data,keyclean,keyBin,wpa_psk)

          else:
             password,data,crackTimeEstimate = self.rules_parameters(wpa_psk,password,data,crackTimeEstimate)

          #MySQL 5.X hash check
          if select == "MySQL 5.X":
            hash_bytes = sha1(data).digest()
            second_hash_encoding = sha1(hash_bytes).hexdigest().upper()
            self.validation("*" + second_hash_encoding ,hash_input,password,wpa_psk,ssid,is_fast_mode,crackTimeEstimate)
            

          #whirlpool hash check
          elif select == "whirlpool":
            wp = wpl(data)
            self.validation(wp.hexdigest(),hash_input,password,wpa_psk,ssid,is_fast_mode,crackTimeEstimate)
            
            
          #checksum sha256 hash check
          elif select == "sha256sum":
            password = password + "\n"
            hash_input = hash_input.replace('  -','')
            sha256sum_hash = sha256(password.encode(self.encoder)).hexdigest()
            self.validation(sha256sum_hash,hash_input,password,wpa_psk,ssid,is_fast_mode,crackTimeEstimate)


          #checksum sha512 hash check
          elif select == "sha512sum":
            password = password + "\n"
            hash_input = hash_input.replace('  -','')
            sha512sum_hash = sha512(password.encode(self.encoder)).hexdigest()
            self.validation(sha512sum_hash,hash_input,password,wpa_psk,ssid,is_fast_mode,crackTimeEstimate) 

        
          #sm3 hash check
          elif select == "sm3":
              supported_hash =  'sm3' if 'sm3' in algorithms_available else ''
              if supported_hash:
                sm3_hash = new('sm3')
                sm3_hash.update(data)
                self.validation(sm3_hash.hexdigest(),hash_input,password,wpa_psk,ssid,is_fast_mode,crackTimeEstimate)
              else:
                crackTimeEstimate = 'time unknown'
                hash_hex = sm3.sm3_hash(func.bytes_to_list(data))
                self.validation(hash_hex,hash_input,password,wpa_psk,ssid,is_fast_mode,crackTimeEstimate)


          #sha512-256 hash check
          elif select == "sha512-256":
              hash_obj = new("sha512_256", data)
              self.validation(hash_obj.hexdigest(),hash_input,password,wpa_psk,ssid,is_fast_mode,crackTimeEstimate)


          #NTLM hash check
          elif select == "NTLM":
              password_utf16 = password.encode('utf-16le')
              hash = MD4.new()
              hash.update(password_utf16)
              self.validation(hash.hexdigest(),hash_input,password,wpa_psk,ssid,is_fast_mode,crackTimeEstimate)


          #SSHA hash check
          elif select == "SSHA":
             b64_data = hash_input[6:]
             decoded = b64decode(b64_data)
             digest = decoded[:20]
             salt = decoded[20:]
             hash_obj = sha1(data)
             hash_obj.update(salt)
             if digest.lower() == hash_obj.digest().lower():
                 self.auxiliary_crack(password,wpa_psk,ssid)
             else:
                 self.faster(is_fast_mode,crackTimeEstimate,password)


          #md5 hash check
          elif select == "md5":
             encryption = md5(data).hexdigest()
             self.validation(encryption,hash_input,password,wpa_psk,ssid,is_fast_mode,crackTimeEstimate)

          #Checking hash shakes
          elif select == "shake-256":
             hash1 = shake_256(data).hexdigest(int(len(hash_input)/2))
             self.validation(hash1,hash_input,password,wpa_psk,ssid,is_fast_mode,crackTimeEstimate)

          elif select == "shake-128":
             shake = shake_128()
             shake.update(data)
             calculated_hash = shake.digest(len(bytes.fromhex(hash_input))).hex()
             self.validation(calculated_hash,hash_input,password,wpa_psk,ssid,is_fast_mode,crackTimeEstimate)

          #checking shacrypt,md5crypt,phpass and apr1 hashes
          #It's a slow hash
          elif select in ["sha256crypt","sha512crypt","md5crypt","apr1","phpass"]:
             if self.hash[select].verify(password, hash_input):
                self.auxiliary_crack(password,wpa_psk,ssid)
             else:
                self.faster(is_fast_mode,crackTimeEstimate,password)

          #DCC2 hash check
          #It's a slow hash
          elif select == "DCC2":
              if self.hash[select].verify(password, hash_input, user):
                 self.auxiliary_crack(password,wpa_psk,ssid)
              else:
                 self.faster(is_fast_mode,crackTimeEstimate,password)


          #bcrypt hash check
          #It's a slow hash
          elif select == "bcrypt":
             if checkpw(data, bytes(hash_input,encoding=self.encoder)):
                self.auxiliary_crack(password,wpa_psk,ssid)
             else:
                self.faster(is_fast_mode,crackTimeEstimate,password)

          #checking  sha1, sha2, sha3 hashes
          elif select in self.hash:
            encryption = self.hash[select](data).hexdigest()
            self.validation(encryption,hash_input,password,wpa_psk,ssid,is_fast_mode,crackTimeEstimate)

          #ripemd-160 hash check
          #It is slow due to its anti-collision implementation.
          elif select == "ripemd-160":
            supported_hash = 'ripemd160' if 'ripemd160' in algorithms_available else ''
            if supported_hash:
               RIPEMD = new("ripemd160", data)
            else:
               RIPEMD = RIPEMD160.new()
               RIPEMD.update(data)
            self.validation(RIPEMD.hexdigest(),hash_input,password,wpa_psk,ssid,is_fast_mode,crackTimeEstimate)

          #Checking blake2 hashes
          elif select in self.hash:
             blas2=self.hash[select](data).hexdigest()
             self.validation(blas2,hash_input,password,wpa_psk,ssid,is_fast_mode,crackTimeEstimate)

          else:
            print("Wrong option!")
            exit(2)


  def process_wpa_passwords(self,password_list,combined,data,keyBin,wpa_psk,ssid,is_fast_mode,crackTimeEstimate,hash_input):
    ''' This method processes a list of passwords, converts them into hashes, and compares them with the hash to be decrypted '''
    backup_password_list = password_list if type(password_list) is str else ''
    validation_str,password_list = self.validate_and_transform_entry(password_list)
    for keyword in password_list:
      if 8 <= len(keyword) <= 63 or validation_str and 8 <= len(backup_password_list) <= 63:
         if validation_str:
            keyclean = backup_password_list.strip()
         else:
            keyclean = keyword
         password = keyclean
         if combined == "y":
            password,data = self.validation_combined(password,data,keyclean,keyBin,wpa_psk)

         else:
             password,data,crackTimeEstimate = self.rules_parameters(wpa_psk,password,data,crackTimeEstimate)

         # Generate WPA-PSK hash using PBKDF2-HMAC-SHA1
         derived_key = pbkdf2_hmac('sha1', password.encode(self.encoder), ssid.encode(self.encoder), 4096, 32)
         if derived_key.hex().lower() == hash_input.lower():
            self.auxiliary_crack(password,wpa_psk,ssid)
         else:
            self.faster(is_fast_mode,crackTimeEstimate,password)



  def dictCrack(self,hash_input,select,is_fast_mode,combined,wait_time,ssid,crackTimeEstimate,wpa_psk,data,keyBin):
     ''' Process dictionary file in chunks to crack a hash or WPA password using appropriate worker functions based on parameters '''
     with open(self.directory_path(),'r',encoding=self.encoder) as keywords_read:
       chunk_size = 512 * 1024
       buffer = ""
       while True:
         chunk = keywords_read.read(chunk_size)
         if wait_time == "y":
             sleep(8)
         if not chunk:
            break
         buffer += chunk
         lines = buffer.splitlines()
         buffer = lines.pop() if not chunk.endswith('\n') else ""
         if not wpa_psk:
            self.hash_cracking_worker(lines,crackTimeEstimate,is_fast_mode,ssid,wpa_psk,hash_input,select,combined)
         else:
            self.process_wpa_passwords(lines,combined,data,keyBin,wpa_psk,ssid,is_fast_mode,crackTimeEstimate,hash_input)
       if buffer:
         if not wpa_psk:
            self.hash_cracking_worker(buffer,crackTimeEstimate,is_fast_mode,ssid,wpa_psk,hash_input,select,combined)
         else:
            self.process_wpa_passwords(buffer,combined,data,keyBin,wpa_psk,ssid,is_fast_mode,crackTimeEstimate,hash_input)
       print("[X] The password does not exist in the dictionary!")
       return


  def crack(self,hash_input,select,is_fast_mode,combined,wait_time):
     ''' The crack function attempts to decrypt a hash by comparing it with a dictionary of words '''
     crackTimeEstimate = self.approximate_duration() if is_fast_mode != "y" else ''
     if combined == "y" or select in ["bcrypt","DCC2","sha256crypt","sha512crypt","md5crypt","apr1","phpass"] or wait_time == "y" and is_fast_mode != "y":
        crackTimeEstimate = "time unknown"
     wpa_psk = False
     self.dictCrack(hash_input,select,is_fast_mode,combined,wait_time,'',crackTimeEstimate,wpa_psk,b'',b'')


  def display_cracking_message(self,is_fast_mode):
     '''  prints a message that the cracking process has already started '''
     if is_fast_mode == "y":
         print("\nCRACKED............\n")
     return


  def crack_wpa_psk(self, hash_input, ssid):
    '''Crack a WPA-PSK hash using PBKDF2-HMAC-SHA1.'''
    wpa_psk = True
    crackTimeEstimate = 'time unknown'
    combined,is_fast_mode,wait_time = self.get_cracking_parameters()
    print("Starting WPA-PSK cracking")
    if is_fast_mode == "y":
      print("\nINFO: The process may take time due to slow hashing")
    self.display_cracking_message(is_fast_mode)
    self.dictCrack(hash_input,'',is_fast_mode,combined,wait_time,ssid,crackTimeEstimate,wpa_psk,b'',b'')
    exit(2)


  def show_help(self):
       '''   Method that displays a help menu  '''
       print("Hasher 1.0. Tool for cracking multiple hashes.")
       print("""
Usage:
     python3 Hasher.py       start the main environment and lead to hash decryption
     python3 Hasher.py -ct7  parameter to enter a Cisco type 7 encoded key
     python3 Hasher.py -sk   parameter to enter the shake-128 hash
     python3 Hasher.py -sk2  parameter to enter the shake-256 hash
     python3 Hasher.py -wpk  parameter to enter the wpa-psk hash
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
|wpa-psk    |
|NTLM       |
|MySQL 5.X  |
|md5crypt   |
|apr1       |
|CiscoType7 |
|DCC2       |
|SSHA       |
|sm3        |
|sha512-256 |
|phpass     |
|whirlpool  |
|sha512sum  |
|sha256sum  |
 ----------
             """)


  def local_db(self,select,hash_input):
     ''' Reads a database to check if the hash given by the user is already there '''
     """Only applies to hashes that do not have a salt and take longer to decrypt"""
     print("Searching in database.......")
     if select in ["NTLM","ripemd-160","sm3"]:
       with open('db.json','r',encoding=self.encoder) as db_read:
         dic_db = loads(db_read.read())
         for hash in dic_db:
           if hash_input.lower() == hash.lower():
               print("\n{***********************SUCCESS***********************}")
               print(f"[✓] Password Found:- {dic_db[hash]}")
               exit(2)
     sleep(1)
     print()
     return


  def cracking_selection(self,hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map):
     ''' Allows the user to choose which hash to crack '''
     valid_hashes = {
     "shake-128": "shake-128",
     "shake-256": "shake-256",
     "sha256crypt": "sha256crypt",
     "sha512crypt": "sha512crypt",
     "md5crypt":"md5crypt",
     "SSHA":"SSHA",
     "phpass":"phpass",
     "DCC2":"DCC2",
     "apr1":"apr1",
     "bcrypt": "bcrypt",
     "MySQL 5.X":"MySQL 5.X"
     }
     select = valid_hashes.get(hash, None)
     if select == "DCC2":
           global user
           dcc2_hash = hash_input.split(':')
           hash_input = dcc2_hash[1]
           user = dcc2_hash[0]
           if not user:
                print("You did not enter the username")
                exit(0)
     elif not select:
       select = input("option: ").strip()
       if select in hash_algorithm_map:
           select = hash_algorithm_map.get(select, None)
     sleep(1)
     system("clear")
     print("""
*****************************
Wait, this may take a while
*****************************
                   """)
     self.local_db(select,hash_input)
     if select in ["phpass","sm3","DCC2","apr1","md5crypt","ripemd-160","NTLM","sha256crypt","sha512crypt","bcrypt"]  and is_fast_mode == "y":
        print("INFO: The process may take time due to slow hashing")
     self.display_cracking_message(is_fast_mode)
     sleep(2)
     self.crack(hash_input,select,is_fast_mode,combined,wait_time)
     return

  def process_secure_hash(self,hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map):
       ''' reports that a secure hash is being cracked '''
       print(f"Type hash: {hash}")
       print(f"{hash.capitalize()}: It's a slow hash. Use small dictionaries for secure hashing")
       sleep(4)
       self.cracking_selection(hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map)
       return


  def auxiliary_main(self,hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map):
     ''' Helper function to validation shake hash '''
     if hash_input:
       if 1 <= len(hash_input) <= 4090:
         self.cracking_selection(hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map)
         exit(2)
       else:
         print("Exceeded the allowed bits of \"16,360\"")
         exit(2)
     else:
         print()
         self.show_help()
         exit(2)


  def parse_auxiliary_arguments(self,hash,hash_algorithm_map):
     ''' Helper function that handles input arguments "-h,--help,-sk,-sk2,-wpk" '''
     if any( help in argv for help in ["-h","--help"]):
               self.show_help()
               exit(2)

     elif "-ct7" in argv:
        print("The key must be in this hexadecimal format and include two numbers at the beginning")
        print("Example: \"0709285E4B1E18091B5C0814\"")
        encrypted = input("Enter the encrypted key: ").strip()
        key = "dsfd;kfoA,.iyewrkldJKD"
        offset = int(encrypted[:2])
        decrypted = ""
        for i in range(2, len(encrypted), 2):
           byte = int(encrypted[i:i+2], 16)
           key_index = (offset + (i - 2) // 2) % len(key)
           decrypted += chr(byte ^ ord(key[key_index]))
        print(f"Password Found => {decrypted}")
        exit(2)

     elif "-sk" in argv:
         combined,is_fast_mode,wait_time = self.get_cracking_parameters()
         hash_input=input("Enter the hash shake-128: ").strip()
         hash = "shake-128"
         self.auxiliary_main(hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map)

     elif "-sk2" in argv:
         combined,is_fast_mode,wait_time = self.get_cracking_parameters()
         hash_input=input("Enter the hash shake-256: ").strip()
         if not hash_input.isalnum():
             if hash_input:
               print("You did not enter a valid hash!")
               print("Enter a hash in \"SHAKE-256\" format")
               exit(2)
         hash = "shake-256"
         self.auxiliary_main(hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map)

     elif "-wpk" in argv:
          #It's a slow hash
          print("INFO: The process is slow due to PBKDF2 hashing")
          print("INFO: It is recommended to use small dictionaries")
          print("INFO: Make sure the keys within the dictionary are approximately 8-63 in length")
          hash_input = input("Enter the WPA hash: ").strip()
          if hash_input:
            hash_wpa_psk = hash_input.split(':')
            hash_input = hash_wpa_psk[1]
            ssid = hash_wpa_psk[0]
            if len(hash_input) == 64 and ssid:
                self.crack_wpa_psk(hash_input, ssid)
            else:
                print("You did not enter a valid hash!")
                print("Enter the network SSID and hash in wpa-psk format")
                exit(2)
          else:
            print()
            self.show_help()
            exit(2)
     return


  def main(self):
   ''' Performs tasks based on what the user selects  '''
   try:
    self.encoder = self.get_encoder()
    hash_algorithm_map = None
    hash = ''
    self.parse_auxiliary_arguments(hash,hash_algorithm_map)
    self.banner()
    print("""
\"INFO: If you want to perform a mask attack
proceed to enter \"n\" and then choose option 3 or
simulate a brute force attack by dictionary using all possible
lengths and combinations with option 2\"
          """)
    self.crunch()
    self.call_modules()
    combined,is_fast_mode,wait_time = self.get_cracking_parameters()
    hash_input=input("Enter the hash: ").strip()
    if len(hash_input) == self.hash['length_md5']:
             print("Type hash:\n1)- md5\n2)- NTLM")
             hash_algorithm_map ={"1":"md5","2":"NTLM"}
             self.cracking_selection(hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map)
    elif len(hash_input) == self.hash['length_sha1']:
             print("Type hash:\n1)- sha1\n2)- ripemd-160")
             hash_algorithm_map ={"1":"sha1","2":"ripemd-160"}
             self.cracking_selection(hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map)
    elif len(hash_input) == self.hash['length_sha224']:
             print("Type hash:\n1)- sha224\n2)- sha3_224")
             hash_algorithm_map ={"1":"sha224","2":"sha3_224"}
             self.cracking_selection(hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map)
    elif len(hash_input) == self.hash['length_sha384']:
             print("Type hash:\n1)- sha384\n2)- sha3_384")
             hash_algorithm_map ={"1":"sha384","2":"sha3_384"}
             self.cracking_selection(hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map)
    elif len(hash_input) == self.hash['length_sha256'] or hash_input.endswith('-') and len(hash_input) == 67:
             print("Type hash:\n1)- sha256\n2)- sha3_256\n3)- blake2s\n4)- sm3\n5)- sha512-256\n6)- sha256sum")
             hash_algorithm_map ={"1":"sha256","2":"sha3_256","3":"blake2s","4":"sm3","5":"sha512-256","6":"sha256sum"}
             self.cracking_selection(hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map)
    elif len(hash_input) == self.hash['length_sha512'] or hash_input.endswith('-') and len(hash_input) == 131:
             print("Type hash:\n1)- sha512\n2)- sha3_512\n3)- blake2b\n4)- whirlpool\n5)- sha512sum")
             hash_algorithm_map ={"1":"sha512","2":"sha3_512","3":"blake2b","4":"whirlpool","5":"sha512sum"}
             self.cracking_selection(hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map)
    elif len(hash_input) == self.hash['length_bcrypt'] and any(v in hash_input[0:5] for v in ["2a$", "2b$", "2y$"]):
             hash = "bcrypt"
             self.process_secure_hash(hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map)
    elif "$5" in hash_input[0:2]:
             hash = "sha256crypt"
             self.process_secure_hash(hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map)
    elif "$6" in hash_input[0:2]:
             hash = "sha512crypt"
             self.process_secure_hash(hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map)
    elif "$1" in hash_input[0:2]:
             hash = "md5crypt"
             self.process_secure_hash(hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map)
    elif "$apr1" in hash_input[0:5]:
             hash = "apr1"
             self.process_secure_hash(hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map)
    elif "{SSHA}" in hash_input[0:7]:
             hash = "SSHA"
             print(f"Type hash: {hash}")
             sleep(2)
             self.cracking_selection(hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map)
    elif hash_input.count(':') == 1:
             hash = "DCC2"
             self.process_secure_hash(hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map)
    elif "*" in hash_input[0:1]:
             hash = "MySQL 5.X"
             print(f"Type hash: {hash}")
             sleep(2)
             self.cracking_selection(hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map)
    elif "$P$" in hash_input[0:3]:
             hash = "phpass"
             self.process_secure_hash(hash_input,hash,is_fast_mode,combined,wait_time,hash_algorithm_map)
    else:
        if hash_input:
          print("""\n
 \"The hash entered is of incorrect length or does not comply
 with the standards supported by the script.
 Please verify and try again.\"
                """ + "\n")
        print()
        self.show_help()

   except KeyboardInterrupt:
        print("BYE!!")
   except FileNotFoundError as e:
        print(f"File not found => {e}")
   except ValueError as F:
        print(f"Type error: {F}")
   except IndexError:
        print("Enter the \"DCC2/WPA-PSK\" hash with the user or SSID")



if __name__ == "__main__":
  crack=Hash_crack()
  crack.main()


__name__="Hasher"
__version__="1.0"
__license__="GPL"
__status__="Finished"
__author__="JP Rojas"
