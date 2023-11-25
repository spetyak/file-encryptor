
# File Encryptor

A file encryptor which is capable of performing encryption/decryption following the 
Advanced Encrytion Standard (AES). The encryptor uses keys of length 128, 192, or 256 bits 
(and IV's of 16 bytes when applicable) and can encrypt/decrypt using the Electronic Code Book (ECB), 
Cipher Block Chain (CBC), or (eventually) Galois Counter (GCM) modes of AES encryption.

Both the ECB and CBC implementations currently run using a single thread and can encrypt ~2000 KB/s 
and decrypt ~830 KB/s. Compared to other more sophisticated implementations this is rather slow. Some
clever tricks and parallelization could help improve this.

## Installation

Here's how to install the file encryptor

## Usage 

To run, use the following syntax:

For ECB:
```bash
./aes -e -aes-ecb -K 00112233445566778899AABBCCDDEEFF -in infile.txt -out outfile.txt
./aes -d -aes-ecb -K 00112233445566778899AABBCCDDEEFF -in infile.txt -out outfile.txt
```

For CBC: 
```bash
./aes -e -aes-cbc -K 00112233445566778899AABBCCDDEEFF -iv 00112233445566778899AABBCCDDEEFF -in infilte.txt -out outfile.txt
./aes -d -aes-cbc -K 00112233445566778899AABBCCDDEEFF -iv 00112233445566778899AABBCCDDEEFF -in infilte.txt -out outfile.txt
```

## Contributing

Please feel free to suggest changes and make pull requests!
