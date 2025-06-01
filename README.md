Disclaimer: 

This tool has been created for educational purposes only. 

The author is not responsible for any misuse of it.

Features:

    1- Multi-process  

    2- Creation of custom dictionaries with crunch

    3- Crack ZIP and RAR file passwords

    4- Perform combined and mask attacks

    5- Fast and simple to use

    6- Support for multiple hashes

    7- Optimized: limited to 1–4 cores and 512 KB RAM per block

    8- Hash Type Detection 

    9- Dictionary or brute force hash decryption

    10- Dictionary attack on exposed SSH services


Included third-party projects:

whirlpool module: https://github.com/oohlaf/python-whirlpool.git

zipcrack: https://github.com/machine1337/zipcrack 

RARNinja: https://github.com/SHUR1K-N/RARNinja-RAR-Password-Cracking-Utility 

Rockyou Dictionary 2023 download link: https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt&ved=2ahUKEwjL6oTfvdKKAxUdSDABHe3UMvwQFnoECBoQAQ&usg=AOvVaw3snAERl1mU6Ccr4WFEazBd 

Rockyou Dictionary 2024 download link: https://t.me/securixy_kz/908

Link to the most commonly used dictionaries: https://github.com/kkrypt0nn/wordlists

Installation:

    cd ~

    git clone https://github.com/LinuxProgramador/Hash_crack

    cd Hash_crack

    bash dependencies.sh

    python3 Hasher.py

To access the help menu and option parameters:

python3 Hasher.py [-h,--help,-sk,-sk2,-wpk,-ct7] 

Supported Hashes:

    MD5

    SHA1

    SHA224

    SHA256

    SHA384

    SHA512

    SHA3-224

    SHA3-256

    SHA3-384

    SHA3-512

    BLAKE2s

    BLAKE2b

    RIPEMD-160

    BCRYPT 

    SHA256CRYPT

    SHA512CRYPT

    SHAKE-128

    SHAKE-256

    WPA-PSK 

    NTLM 

    MySQL 5.X

    MD5CRYPT

    APR1

    CISCO TYPE 7 

    DCC2

    SSHA

    SM3

    SHA512-256

    PHPASS

    WHIRLPOOL 

    SHA256SUM

    SHA512SUM

    ARGON2ID

    SCRYPT

    PBKDF2_SHA256

Important Notes: 

INFO: This tool was designed mostly for the Termux environment, since tools like John the Ripper or Hashcat are not compatible with Termux.

INFO: Argon2id is only available in single-core modules, for example (Hasher / Brute_force)

INFO: Scrypt is only available in single-core modules, for example (Hasher / Brute_force)

1- If you want to use your own dictionary, you should name it wordlist.txt and place it in the Hash_crack directory.

2- Success in cracking passwords from ZIP and RAR files depends heavily on the program used to compress them. Decryption is more likely to work if they were compressed using console tools such as zip or rar.

3- In "DCC2/WPA-PSK" hashes enter the user or SSID along with the hash:
For example: 

    WPA-PSK: MyNetwork:c5846b79d776cf7c0973edf6e8bb0778da330b1a92d18f6664557b1d9b7498dd

    DCC2: root:e7f9a1ba77b1d0406ab52783b2b9636a


Quit the program:

Press CTRL + C
