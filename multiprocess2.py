#!/usr/bin/python3

from multiprocessing import Process,Queue,Event
from hashlib import pbkdf2_hmac
from sys import exit
from passlib.hash import sha256_crypt, sha512_crypt, md5_crypt, apr_md5_crypt, msdcc2, phpass
from os import path, system
from bcrypt import checkpw
from time import sleep

hashes = {
    'sha256crypt': sha256_crypt,
    'sha512crypt': sha512_crypt,
    'phpass':phpass,
    'md5crypt': md5_crypt,
    'apr1':apr_md5_crypt
}

def get_encoder():
    print("INFO: For compatibility reasons with certain symbols, choose encoder:")
    print("1) latin-1\n2) utf-8")
    encoder_text = input("option: ")
    select_encoder = "latin-1" if encoder_text == "1" else "utf-8"
    return select_encoder

def crack(target_hash, word, select, ssid, found, queue, encoder):
    if select == "bcrypt":
        if checkpw(word.encode(encoder), bytes(target_hash, encoding=encoder)):
            queue.put(f"Key found: {word}")
            found.set()
    elif select == "DCC2":
       sleep(200 / 1e6)
       if msdcc2.verify(word, target_hash, user):
            queue.put(f"Key found: {word}")
            found.set()
    elif select in hashes:
        if select == 'sha512crypt':
           sleep(200 / 1e6)
        if hashes[select].verify(word, target_hash):
            queue.put(f"Key found: {word}")
            found.set()
    elif select == "wpa-psk":
        if 8 <= len(word) <= 63:
            derived_key = pbkdf2_hmac('sha1', word.encode(encoder), ssid.encode(encoder), 4096, 32)
            if derived_key.hex().lower() == target_hash.lower():
                queue.put(f"SSID: {ssid}\nKey found: {word}")
                found.set()

def check_hash(rute, target_hash, select, ssid, found, queue, wait_time, encoder, chunk_size=512 * 1024):
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
                    crack(target_hash, word, select, ssid, found, queue, encoder)
            if buffer:
                crack(target_hash, buffer.strip(), select, ssid, found, queue, encoder)
    except FileNotFoundError:
        queue.put(f"File not found: {rute}")
    except ValueError as e:
        queue.put(f"Type error: {e}")
    except Exception as e:
        queue.put(f"Error processing {rute}: {e}")

def main():
    try:
        encoder = get_encoder()
        sleep(1)
        system("clear")
        ssid = None
        
        rute1 = input("Enter the path of dictionary -1: ").strip()
        rute2 = input("Enter the path of dictionary -2: ").strip()
        rute3 = input("Enter the path of dictionary -3: ").strip()
        rute4 = input("Enter the path of dictionary -4: ").strip()
        wait_time = input("You want to avoid overheating the processor (y/n): ").strip().lower()
        target_hash = input("Enter the hash: ").strip()
        validation_hash_wpa_dcc2 = target_hash.split(':') if target_hash.count(':') == 1 else list('00')
        
        if any(v in target_hash[0:5] for v in ["2a$", "2b$", "2y$"]):
            select = "bcrypt"
        elif target_hash.startswith("$5"):
            select = "sha256crypt"
        elif target_hash.startswith("$6"):
            select = "sha512crypt"
        elif target_hash.startswith("$1"):
             select = "md5crypt"
        elif target_hash.startswith("$apr1"):
            select = "apr1"
        elif target_hash.startswith("$P$"):
            select = "phpass"
        elif len(validation_hash_wpa_dcc2[1]) == 64:
            print("INFO: Make sure the keys within the dictionary are approximately 8-63 in length")
            select = "wpa-psk"
            target_hash = validation_hash_wpa_dcc2[1]
            ssid = validation_hash_wpa_dcc2[0]
            if not ssid:
                print("You did not enter the SSID name")
                exit(0)
        elif len(validation_hash_wpa_dcc2[1]) == 32:
             select = "DCC2"
             global user
             target_hash = validation_hash_wpa_dcc2[1]
             user = validation_hash_wpa_dcc2[0]
             if not user:
                print("You did not enter the username")
                exit(0)
        else:
            print("You did not enter a valid hash!")
            exit(0)

    except KeyboardInterrupt:
        print()
        exit(0)
    except IndexError:
        print("Enter the \"DCC2/WPA-PSK\" hash with the user or SSID")
        exit(0)

    found = Event()
    queue = Queue()

    print("Starting parallel checking..")

    processes = [
        Process(target=check_hash, args=(rute, target_hash, select, ssid, found, queue, wait_time, encoder))
        for rute in [rute1, rute2, rute3, rute4]
    ]

    for process in processes:
        process.start()

    try:
        while any(process.is_alive() for process in processes):
            while not queue.empty():
                print(queue.get())
                found.set()
            if found.is_set():
                for process in processes:
                    process.terminate()
                break
            for process in processes:
                process.join(timeout=1)

        if found.is_set():
            for process in processes:
                process.terminate()

    except KeyboardInterrupt:
        print()
        for process in processes:
            process.terminate()
        exit(0)
    except ValueError as e:
        print(f"Type error: {e}")
        for process in processes:
            process.terminate()
        exit(0)

    while not queue.empty():
        print(queue.get())

    if not found.is_set():
        print("Key not found in the dictionaries.")
        print("Checking completed.")
        exit(1)

    print("Checking completed.")

if __name__ == "__main__":
    main()


__status__ = "Finish"
