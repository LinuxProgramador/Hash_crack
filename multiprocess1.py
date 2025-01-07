import multiprocessing
from Crypto.Hash import RIPEMD160
from hashlib import md5,sha1,sha224,sha384,sha256,sha512,sha3_256,sha3_224,sha3_384,sha3_512,blake2s,blake2b,shake_128,shake_256
from sys import exit

hashes = {
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
    'blake2s':blake2s
    }


try:
  rute1 = input("Enter the path of the first dictionary: ").strip()
  rute2 = input("Enter the path of the second dictionary: ").strip()
  hash_objetivo = input("Enter the hash to be decrypted: ").strip()
  print()
  print("supported hashes:")
  print("""
 _________
|md5       |
|sha1      |
|sha224    |
|sha384    |
|sha256    |
|sha512    |
|sha3_224  |
|sha3_384  |
|sha3_256  |
|sha3_512  |
|blake2s   |
|blake2b   |
|shake-128 |
|shake-256 |
|rypemd-160|
 __________
        """)

  select = input("Enter the hash type: ").strip().lower()

except KeyboardInterrupt:
      print()
      exit(0)
except FileNotFoundError as F:
      print(f"invalid path: {F}")


def crack(hash_objetivo,rute,palabra,evento):

   data = palabra.encode()

   if select == "md5":
       hash_generado = md5(palabra.encode()).hexdigest()
       if hash_generado == hash_objetivo:
          print(f"Key found in {rute}: {palabra}")
          evento.set()
          return

   elif select in hashes:
          hash_generado = hashes[select](palabra.encode('latin-1')).hexdigest()
          if hash_generado == hash_objetivo:
              print(f"Key found in {rute}: {palabra}")
              evento.set()
              return

   elif select in hashes:
          hash_generado = hashes[select](data).hexdigest()
          if hash_generado == hash_objetivo:
              print(f"Key found in {rute}: {palabra}")
              evento.set()
              return

   elif select == "shake-256":
          hash_generado = shake_256(data).hexdigest(int(len(hash_objetivo)/2))
          if hash_generado == hash_objetivo:
              print(f"Key found in {rute}: {palabra}")
              evento.set()
              return

   elif select == "shake-128":
          shake = shake_128()
          shake.update(data)
          hash_generado = shake.digest(len(bytes.fromhex(hash_objetivo))).hex()
          if hash_generado == hash_objetivo:
             print(f"Key found in {rute}: {palabra}")
             evento.set()
             return

   elif select == "rypemd-160":
          RIPEMD = RIPEMD160.new()
          RIPEMD.update(data)
          if RIPEMD.hexdigest() == hash_objetivo:
              print(f"Key found in {rute}: {palabra}")
              evento.set()
              return
   else:
        print("Wrong name!")
        proceso1.terminate()
        proceso2.terminate()
        exit(0)

def comprobar_hash(rute, hash_objetivo, evento,  chunk_size=1024 * 1024):
    try:
        with open(rute, 'r', encoding='latin-1') as file:
            while not evento.is_set():
                chunk = file.readlines(chunk_size)
                if not chunk:
                    break

                for line in chunk:
                    palabra = line.strip()
                    crack(hash_objetivo,rute,palabra,evento)
    except FileNotFoundError:
        print(f"File not found: {rute}")
    except Exception as e:
        print(f"Processing error {rute}: {e}")

if __name__ == "__main__":
    evento = multiprocessing.Event()

    print("Starting parallel checking...")


    proceso1 = multiprocessing.Process(target=comprobar_hash, args=(rute1, hash_objetivo, evento))
    proceso2 = multiprocessing.Process(target=comprobar_hash, args=(rute2, hash_objetivo, evento))


    proceso1.start()
    proceso2.start()

    try:

        proceso1.join()
        proceso2.join()
    except KeyboardInterrupt:
        print("Interruption detected. Closing...")
        evento.set()
        proceso1.terminate()
        proceso2.terminate()
        exit(0)

    if evento.is_set():
        print("Key found. Ending processes.")
    else:
        print("Key not found in any of the dictionaries.")

    print("Checking completed.")
