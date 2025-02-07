import multiprocessing
from Crypto.Hash import RIPEMD160,MD4
from hashlib import md5, sha1, sha224, sha384, sha256, sha512, sha3_256, sha3_224, sha3_384, sha3_512, blake2s, blake2b, shake_128, shake_256
from sys import exit,argv
from time import sleep
from os import system


#The code has some flaws when entering the hash name, variable and function names in Spanish and English
#and others of the sort, but it does serve its purpose. 


hashes = {
    'sha1': sha1,
    'sha224': sha224,
    'sha384': sha384,
    'sha256': sha256,
    'sha512': sha512,
    'sha3_224': sha3_224,
    'sha3_384': sha3_384,
    'sha3_256': sha3_256,
    'sha3_512': sha3_512,
    'blake2b': blake2b,
    'blake2s': blake2s,
    'length_md5':32,
    'length_sha1':40,
    'length_sha224':56,
    'length_sha256':64,
    'length_sha384':96,
    'length_sha512':128
}

global encoder
try:
  if not any( help in argv for help in ["-h","--help"]):
     print("INFO: For compatibility reasons with certain symbols, Do you choose encoder:")
     print("1) latin-1\n2) utf-8")
     encoder_text = input("option: ")
     if encoder_text == "1":
         encoder = "latin-1"
     elif encoder_text == "2":
         encoder = "utf-8"
     else:
         encoder = "latin-1"
     sleep(1)
     system("clear")
except KeyboardInterrupt:
    print("BYE!!")
    exit(2)
    
def crack(hash_objetivo, palabra, select, evento, queue):
    data = palabra.encode()

    if select == "ntlm":
        password_utf16 = palabra.encode('utf-16le')
        hash = MD4.new()
        hash.update(password_utf16)
        hash_generado = hash.hexdigest()
    elif select == "md5":
        hash_generado = md5(data).hexdigest()
    elif select in hashes:
        hash_generado = hashes[select](data).hexdigest()
    elif select == "shake-256":
        hash_generado = shake_256(data).hexdigest(len(hash_objetivo) // 2)
    elif select == "shake-128":
        shake = shake_128()
        shake.update(data)
        hash_generado = shake.digest(len(bytes.fromhex(hash_objetivo))).hex()
    elif select == "ripemd-160":
        RIPEMD = RIPEMD160.new()
        RIPEMD.update(data)
        hash_generado = RIPEMD.hexdigest()
    else:
        print("Wrong hash name!")
        evento.set()
        proceso1.terminate()
        proceso2.terminate()
        exit(0)
        return

    if hash_generado.lower() == hash_objetivo.lower():
        print(f"Key found: {palabra}")
        evento.set()
        queue.put(palabra)
        return

def comprobar_hash(rute, hash_objetivo, select, evento, queue, wait_time, chunk_size=512 * 1024):
    try:
        
        with open(rute, 'r', encoding=encoder) as file:
           buffer = ""
           while not evento.is_set():
               chunk = file.read(chunk_size)
               if wait_time == "y":
                    sleep(10)
               if not chunk:
                  break
               buffer += chunk
               lines = buffer.splitlines()
               buffer = lines[-1] if len(lines) > 1 else ""
               for palabra in lines[:-1]:
                    crack(hash_objetivo, palabra, select, evento, queue)
           if buffer:
              crack(hash_objetivo, buffer.strip(), select, evento, queue)
    except FileNotFoundError:
        print(f"File not found: {rute}")
    except ValueError as F:
        print(f"Type error: {F}")
    except Exception as e:
        print(f"Processing error {rute}: {e}")

def process_files(rute1, rute2, rute3, rute4, hash_objetivo, select, wait_time):
    evento = multiprocessing.Event()
    queue = multiprocessing.Queue()

    print("Starting parallel checking...")

    proceso1 = multiprocessing.Process(target=comprobar_hash, args=(rute1, hash_objetivo, select, evento, queue, wait_time))
    proceso2 = multiprocessing.Process(target=comprobar_hash, args=(rute2, hash_objetivo, select, evento, queue, wait_time))
    proceso3 = multiprocessing.Process(target=comprobar_hash, args=(rute3, hash_objetivo, select, evento, queue, wait_time))
    proceso4 = multiprocessing.Process(target=comprobar_hash, args=(rute4, hash_objetivo, select, evento, queue, wait_time))
 
    proceso1.start()
    proceso2.start()
    proceso3.start()
    proceso4.start()
    try:
        proceso1.join()
        proceso2.join()
        proceso3.join()
        proceso4.join()
    except KeyboardInterrupt:
        print("Interruption detected. Closing...")
        evento.set()
        proceso1.terminate()
        proceso2.terminate()
        proceso3.terminate()
        proceso4.terminate()
        exit(0)

    if evento.is_set():
        found_word = queue.get()
        print(f"Key found: {found_word}")
    else:
        print("Key not found in any of the dictionaries.")

    print("Checking completed.")

if __name__ == "__main__":
    try:
        rute1 = input("Enter the path of the first dictionary: ").strip()
        rute2 = input("Enter the path of the second dictionary: ").strip()
        rute3 = input("Enter the path of the third dictionary: ").strip()
        rute4 = input("Enter the path of the fourth dictionary: ").strip()
        hash_objetivo = input("Enter the hash to be decrypted: ").strip()
        if len(hash_input) == hashes['length_md5']:
             print(f"Type hash:\n1)- md5\n2)- NTLM\n128)- shake-128\n256)- shake-256")
             hash_algorithm_map ={"1":"md5","2":"NTLM","128":"shake-128","256":"shake-256"}
             select = input("option: ")
             select = hash_algorithm_map[select]

        elif len(hash_input) == hashes['length_sha1']:
             print("Type hash:\n1)- sha1\n2)- ripemd-160\n128)- shake-128\n256)- shake-256")
             hash_algorithm_map ={"1":"sha1","2":"ripemd-160","128":"shake-128","256":"shake-256"}
             select = input("option: ")
             select = hash_algorithm_map[select]

        elif len(hash_input) == hashes['length_sha224']:
             print("Type hash:\n1)- sha224\n2)- sha3_224\n128)- shake-128\n256)- shake-256")
             hash_algorithm_map ={"1":"sha224","2":"sha3_224","128":"shake-128","256":"shake-256"}
             select = input("option: ")
             select = hash_algorithm_map[select]

        elif len(hash_input) == hashes['length_sha384']:
             print("Type hash:\n1)- sha384\n2)- sha3_384\n128)- shake-128\n256)- shake-256")
             hash_algorithm_map ={"1":"sha384","2":"sha3_384","128":"shake-128","256":"shake-256"}
             select = input("option: ")
             select = hash_algorithm_map[select]

        elif len(hash_input) == hashes['length_sha256']:
             print("Type hash:\n1)- sha256\n2)- sha3_256\n3)- blake2s\n128)- shake-128\n256)- shake-256")
             hash_algorithm_map ={"1":"sha256","2":"sha3_256","3":"blake2s","128":"shake-128","256":"shake-256"}
             select = input("option: ")
             select = hash_algorithm_map[select]

        elif len(hash_input) == hashes['length_sha512']:
             print("Type hash:\n1)- sha512\n2)- sha3_512\n3)- blake2b\n128)- shake-128\n256)- shake-256")
             hash_algorithm_map ={"1":"sha512","2":"sha3_512","3":"blake2b","128":"shake-128","256":"shake-256"}
             select = input("option: ")
             select = hash_algorithm_map[select]
        wait_time = input("You want to avoid overheating the processor (y/n): ").strip().lower()
        if select in ["ripemd-160","ntlm"]:
            print(f"{select} tends to take a little longer")

    except KeyboardInterrupt:
        print()
        exit(0)
    except FileNotFoundError as F:
        print(f"invalid path: {F}")

    process_files(rute1, rute2, rute3, rute4, hash_objetivo, select, wait_time)


__status__="beta"
