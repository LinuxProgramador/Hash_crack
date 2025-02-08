import multiprocessing
from hashlib import pbkdf2_hmac
from sys import exit,argv
from passlib.hash import sha256_crypt, sha512_crypt
from os import path,system
from bcrypt import checkpw
from time import sleep


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


def crack(target_hash, word, select, ssid, found, queue):
    if select == "bcrypt":
        if checkpw(word.encode(), bytes(target_hash, encoding=encoder)):
            queue.put(f"Key found: {word}")
            found.set()
            return        
    elif select in hashes:
        if hashes[select].verify(word, target_hash):
            queue.put(f"Key found: {word}")
            found.set()
            return
    elif select == "wpa-psk":
        if 8 <= len(word) <= 63:
            derived_key = pbkdf2_hmac('sha1', word.encode(), ssid.encode(), 4096, 32)
            if derived_key.hex().lower() == target_hash.lower():
                queue.put(f"SSID: {ssid}\nKey found: {word}")
                found.set()
                return

def check_hash(rute, target_hash, select, ssid, found, queue, wait_time, chunk_size=512 * 1024):
    try:
        with open(rute, 'r', encoding=encoder) as file:
            buffer = ""
            while not found.is_set():                                                                         
                chunk = file.read(chunk_size)
                if wait_time == "y":
                    sleep(15)
                if not chunk:
                    break
                buffer += chunk
                lines = buffer.splitlines()
                buffer = lines[-1] if len(lines) > 1 else ""
                for word in lines[:-1]:
                    crack(target_hash, word, select, ssid, found, queue)
            if buffer:
                crack(target_hash, buffer.strip(), select, ssid, found, queue)
    except FileNotFoundError:
        queue.put(f"File not found: {rute}")
    except ValueError as F:
        print(f"Type error: {F}")
    except Exception as e:
        queue.put(f"Error processing {rute}: {e}")

if __name__ == "__main__":
    try:
        rute1 = input("Enter the path of the first dictionary: ").strip()
        rute2 = input("Enter the path of the second dictionary: ").strip()
        rute3 = input("Enter the path of the third dictionary: ").strip()
        rute4 = input("Enter the path of the fourth dictionary: ").strip()
        target_hash = input("Enter the hash to be decrypted: ").strip()
        if any(v in target_hash[0:5] for v in ["2a$", "2b$", "2y$"]):
             select = "bcrypt"
        elif "$5" in target_hash[0:2]:
             select = "sha256crypt"
        elif "$6" in target_hash[0:2]:
             select = "sha512crypt"
        elif len(target_hash) == 64:
             select = "wpa-psk"
        if select == "wpa-psk":
            print("INFO: Make sure the keys within the dictionary are approximately 8-63 in length")
            sleep(4)
        ssid = input("Enter the SSID (if WPA-PSK): ").strip() if select == "wpa-psk" else None
        wait_time = input("You want to avoid overheating the processor (y/n): ").strip().lower()
    except KeyboardInterrupt:
        print()
        exit(0)

    found = multiprocessing.Event()
    queue = multiprocessing.Queue()

    print("Starting parallel checking..")

    process1 = multiprocessing.Process(target=check_hash, args=(rute1, target_hash, select, ssid, found, queue, wait_time))
    process2 = multiprocessing.Process(target=check_hash, args=(rute2, target_hash, select, ssid, found, queue, wait_time))
    process3 = multiprocessing.Process(target=check_hash, args=(rute3, target_hash, select, ssid, found, queue, wait_time))
    process4 = multiprocessing.Process(target=check_hash, args=(rute4, target_hash, select, ssid, found, queue, wait_time))
    
    process1.start()
    process2.start()
    process3.start()
    process4.start()

    try:
        while process1.is_alive() or process2.is_alive() or process3.is_alive() or process4.is_alive():
            while not queue.empty():
                print(queue.get())
                found.set()
            if found.is_set():
                process1.terminate()
                process2.terminate()
                process3.terminate()
                process4.terminate()
                break
            process1.join(timeout=1)
            process2.join(timeout=1)
            process3.join(timeout=1)                                                             
            process4.join(timeout=1)

        if found.is_set():
            process1.terminate()
            process2.terminate()
            process3.terminate()
            process4.terminate()
    except KeyboardInterrupt:
        print()
        process1.terminate()
        process2.terminate()
        process3.terminate()
        process4.terminate()
        exit(0)
    except ValueError as F:
        print(f"Type error: {F}")

    while not queue.empty():
        print(queue.get())

    if not found.is_set():
        print("Key not found in the dictionaries.")
        print("Checking completed.")
        exit(1)

    print("Checking completed.")



__status__="beta"
