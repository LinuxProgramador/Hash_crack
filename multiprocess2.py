import multiprocessing
from hashlib import pbkdf2_hmac
from sys import exit,argv
from passlib.hash import sha256_crypt, sha512_crypt
from os import path,system
from bcrypt import checkpw
from time import sleep

#The code has some flaws, but it serves its purpose 

hashes = {
    'sha256crypt': sha256_crypt,
    'sha512crypt': sha512_crypt
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


def crack(hash_objetivo, palabra, select, ssid, encontrado, queue):
    if select == "bcrypt":
        if checkpw(palabra.encode(), bytes(hash_objetivo, encoding=encoder)):
            queue.put(f"Key found: {palabra}")
            encontrado.set()
            return        
    elif select in hashes:
        if hashes[select].verify(palabra, hash_objetivo):
            print(f"key found: {palabra}")
            queue.put(f"Key found: {palabra}")
            encontrado.set()
            return
    elif select == "wpa-psk":
        if 8 <= len(palabra) <= 63:
            derived_key = pbkdf2_hmac('sha1', palabra.encode(), ssid.encode(), 4096, 32)
            if derived_key.hex().lower() == hash_objetivo.lower():
                queue.put(f"SSID: {ssid}\nKey found: {palabra}")
                encontrado.set()
                return

def comprobar_hash(rute, hash_objetivo, select, ssid, encontrado, queue, wait_time, chunk_size=512 * 1024):
    try:
        with open(rute, 'r', encoding=encoder) as file:
            buffer = ""
            while not encontrado.is_set():                                                                         
                chunk = file.read(chunk_size)
                if wait_time == "y":
                    sleep(15)
                if not chunk:
                    break
                buffer += chunk
                lines = buffer.splitlines()
                buffer = lines[-1] if len(lines) > 1 else ""
                for palabra in lines[:-1]:
                    crack(hash_objetivo, palabra, select, ssid, encontrado, queue)
            if buffer:
                crack(hash_objetivo, buffer.strip(), select, ssid, encontrado, queue)
    except FileNotFoundError:
        queue.put(f"File not found: {rute}")
    except Exception as e:
        queue.put(f"Error processing {rute}: {e}")

if __name__ == "__main__":
    try:
        rute1 = input("Enter the path of the first dictionary: ").strip()
        rute2 = input("Enter the path of the second dictionary: ").strip()
        rute3 = input("Enter the path of the third dictionary: ").strip()
        rute4 = input("Enter the path of the fourth dictionary: ").strip()
        hash_objetivo = input("Enter the hash to be decrypted: ").strip()
        print("Supported hashes:\n- bcrypt\n- sha512crypt\n- sha256crypt\n- wpa-psk")
        select = input("Enter the hash type: ").strip().lower()
        ssid = input("Enter the SSID (if WPA-PSK): ").strip() if select == "wpa-psk" else None
        wait_time = input("You want to avoid overheating the processor (y/n): ").strip().lower()
    except KeyboardInterrupt:
        print()
        exit(0)

    encontrado = multiprocessing.Event()
    queue = multiprocessing.Queue()

    print("Starting parallel checking..")

    proceso1 = multiprocessing.Process(target=comprobar_hash, args=(rute1, hash_objetivo, select, ssid, encontrado, queue, wait_time))
    proceso2 = multiprocessing.Process(target=comprobar_hash, args=(rute2, hash_objetivo, select, ssid, encontrado, queue, wait_time))
    proceso3 = multiprocessing.Process(target=comprobar_hash, args=(rute3, hash_objetivo, select, ssid, encontrado, queue, wait_time))
    proceso4 = multiprocessing.Process(target=comprobar_hash, args=(rute4, hash_objetivo, select, ssid, encontrado, queue, wait_time))
    
    proceso1.start()
    proceso2.start()
    proceso3.start()
    proceso4.start()

    try:
        while proceso1.is_alive() or proceso2.is_alive() or proceso3.is_alive() or proceso4.is_alive():
            while not queue.empty():
                print(queue.get())
                encontrado.set()
            if encontrado.is_set():
                proceso1.terminate()
                proceso2.terminate()
                proceso3.terminate()
                proceso4.terminate()
                break
            proceso1.join(timeout=1)
            proceso2.join(timeout=1)
            proceso3.join(timeout=1)                                                             
            proceso4.join(timeout=1)

        if encontrado.is_set():
            proceso1.terminate()
            proceso2.terminate()
            proceso3.terminate()
            proceso4.terminate()
    except KeyboardInterrupt:
        print()
        proceso1.terminate()
        proceso2.terminate()
        proceso3.terminate()
        proceso4.terminate()
        exit(0)

    while not queue.empty():
        print(queue.get())

    if not encontrado.is_set():
        print("Key not found in the dictionaries.")
        print("Checking completed.")
        exit(1)

    print("Checking completed.")



__status__="beta"
