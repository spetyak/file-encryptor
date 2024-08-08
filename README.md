
# File Encryptor

A file encryptor which is capable of performing encryption/decryption following the 
Advanced Encrytion Standard (AES) provided by the National Institute of Standards and Technology FIPS-197. 
The encryptor uses keys of length 128, 192, or 256 bits (and IV's of 16 bytes when applicable) and 
can encrypt/decrypt using the Electronic Code Book (ECB), Cipher Block Chain (CBC), or (eventually) 
Galois Counter (GCM) modes of AES encryption.

Both the ECB and CBC implementations currently run using a single thread and can encrypt ~2000 KB/s 
and decrypt ~830 KB/s. Compared to other more sophisticated implementations this is rather slow. Some
clever tricks and parallelization could help improve this.

## Usage 

To run, simply run the executable:

```bash
./aes 
```

The shell will then prompt the user to choose whether they'd like to encrypt/decrypt, input/output sources, and a key and initialization vector.

## Contributing

Please feel free to suggest changes and make pull requests!
