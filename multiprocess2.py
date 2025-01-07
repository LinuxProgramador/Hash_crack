import multiprocessing
from hashlib import pbkdf2_hmac
from bcrypt import checkpw
from sys import exit
from passlib.hash import sha256_crypt,sha512_crypt

hashes = {
'sha256crypt':sha256_crypt,
'sha512crypt':sha512_crypt
}


try:

  rute1 = input("Enter the path of the first dictionary: ").strip()
  rute2 = input("Enter the path of the second dictionary: ").strip()
  hash_objetivo = input("Enter the hash to be decrypted: ").strip()
  print()
  print("supported hashes:")
  print("""
 ___________
|bcrypt     |
|sha512crypt|
|sha256crypt|
|wpa-psk    |
 ___________
        """)

  select = input("Enter the hash type: ").strip().lower()
  if select == "wpa-psk":
     ssid = input("Enter the SSID: ").strip()

except KeyboardInterrupt:
      print()
      exit(0)
except FileNotFoundError as F:
      print(f"invalid path: {F}")


def crack(hash_objetivo,rute,palabra,encontrado):

    if select == "bcrypt":
      if checkpw(palabra.encode(),bytes(hash_objetivo,encoding="latin-1")):
        print(f"Key found in {rute}: {palabra}")
        encontrado.set()
        return
    elif select in hashes:
       if hashes[select].verify(palabra, hash_objetivo):
         print(f"Key found in {rute}: {palabra}")
         encontrado.set()
         return
    elif select == "wpa-psk":
         if len(palabra) >= 9 and len(palabra) <= 64:
           derived_key = pbkdf2_hmac('sha1', palabra.encode(), ssid.encode(), 4096, 32)
           if derived_key.hex() == hash_objetivo:
               print(f"SSID: {ssid}")
               print(f"Key found in {rute}: {palabra}")
               encontrado.set()
               return
    else:
        print("Wrong name!")
        proceso1.terminate()
        proceso2.terminate()
        exit(0)


def comprobar_hash(rute, hash_objetivo, encontrado, chunk_size=512 * 1024):
    try:
        with open(rute, 'r', encoding='latin-1') as file:
            while not encontrado.is_set():
                lines = file.readlines(chunk_size)
                if not lines:
                    break

                for line in lines:
                    palabra = line.strip()
                    crack(hash_objetivo,rute,palabra,encontrado)
    except FileNotFoundError:
        print(f"File not found: {rute}")
    except Exception as e:
        print(f"Processing error {rute}: {e}")

if __name__ == "__main__":
    encontrado = multiprocessing.Event()

    print("Starting parallel checking...")


    proceso1 = multiprocessing.Process(target=comprobar_hash, args=(rute1, hash_objetivo, encontrado))
    proceso2 = multiprocessing.Process(target=comprobar_hash, args=(rute2, hash_objetivo, encontrado))


    proceso1.start()
    proceso2.start()

    try:

        while not encontrado.is_set():
            proceso1.join(timeout=1)
            proceso2.join(timeout=1)


        if encontrado.is_set():
            print("Key found, closing script")
            proceso1.terminate()
            proceso2.terminate()
            exit(0)

    except KeyboardInterrupt:
        print("\nInterruption detected. Closing...")

        proceso1.terminate()
        proceso2.terminate()
        exit(0)

    print("Checking completed.")
