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


Included third-party projects:

zipcrack: https://github.com/machine1337/zipcrack 

RARNinja: https://github.com/SHUR1K-N/RARNinja-RAR-Password-Cracking-Utility 

Rockyou Dictionary 2023 download link: https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt&ved=2ahUKEwjL6oTfvdKKAxUdSDABHe3UMvwQFnoECBoQAQ&usg=AOvVaw3snAERl1mU6Ccr4WFEazBd 

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

    NTLMV2 

    DCC2

    SSHA

Important Notes: 

1- If you want to use your own dictionary, you should name it wordlist.txt and place it in the Hash_crack directory.

2- Success in cracking passwords from ZIP and RAR files depends heavily on the program used to compress them. Decryption is more likely to work if they were compressed using console tools such as zip or rar.

3- Recommended entry for NTLMV2, avoid entering the user and the '::' at the beginning.
For example:  WIN14EQ22AUEQQ:1122334455667788:7D9F243618A9F7D0A67E33C32CADOF6D:01010000000000007B1A5D1F4184D80165B72B4E1C351E52000000000200060053004D0042000100160053004D0042002D00540804F004F004C004B00490054000400120073006D0062002E006C006F00630061006C0003002800730065007208076006500720032003000300033002E£0073006D0062002E006C006F00630061006C00050012007300600062002£806C006F00630061006C00080030003000000000000000010000000020000042D10CB967E565082DB9764DD27D0466049D29CCB6AE09136F0E9AF0C8420BA60A001000000000000000000000000000000000000900200048005400540050002F007000720069006E0074007300650072007600650072000000000000000000

Quit the program:

Press CTRL + C
