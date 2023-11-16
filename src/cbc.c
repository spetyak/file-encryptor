#include "../inc/aes.h"
#include "../inc/cbc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// implement Cipher Block Chain mode 

// should we do the encyrption in a function (other than main) in aes.c 
// so that we can call it from here and gcm.c?

// IV is 16 bytes (same as block)

void xor(uint8_t** a, uint8_t** b) {

    for (int i = 0; i < BUFFER_SIZE; i++)
    {

        (*a)[i] ^= (*b)[i];

    }

}



// ENCRYPT
// step 1: read in block of plaintext
//    L step 2: xor with IV 
//    OR (if past first time)
//    L step 2: xor with previously generated ciphertext
// step 3: encrypt block using key
// step 4: retrieve cipher text block
// repeat steps 1 through 4

// DECRYPT
// step 1: read in block of ciphertext (* hold on to it)
// step 2: decrypt block using key
//    L step 3: xor with IV
//    OR (if past first time)
//    L step 3: xor with previous cipher text block *
// step 4: retrieve plaintext
// repeat steps 1 through 4





/*
 * inBuf        - the input to the encryption algorithm
 * prevCipher   - the previously computed cipher
 * keySchedule  - the key schedule
 * numRounds    - the number of encryption rounds, specific to each key length
 * iv           - the initialization vector
 * firstRun     - 1 for first run, 0 otherwise
 */
void cbcEncrypt(uint8_t* inBuf, uint8_t* prevCipherOut, uint8_t* prevCipherIn, int numRounds, uint8_t* iv, int* firstRun) {

    if (*firstRun) 
    {
        // xor inBuf with iv
        xor(&inBuf, &iv);
        (*firstRun)--;
    }
    else
    {
        // xor with previously generated ciphertext
        xor(&inBuf, &prevCipherIn);
    }

    aesEncrypt(inBuf, numRounds);

    // prevCipher = inBuf;
    memcpy(prevCipherOut, inBuf, BUFFER_SIZE);

}

/*
 * inBuf        - the input to the encryption algorithm
 * prevCipher   - the previously computed cipher
 * keySchedule  - the key schedule
 * numRounds    - the number of encryption rounds, specific to each key length
 * iv           - the initialization vector
 * firstRun     - 1 for first run, 0 otherwise
 */
void cbcDecrypt(uint8_t* inBuf, uint8_t* prevCipherOut, uint8_t* prevCipherIn, int numRounds, uint8_t* iv, int* firstRun) {

    // prevCipher = inBuf;
    memcpy(prevCipherOut, inBuf, BUFFER_SIZE); // this is probably overwriting the previous cipher we want (NOT GOOD)

    // figure out how to get previous cipher out so it doesn't get overwritten

    aesDecrypt(inBuf, numRounds);

    if (*firstRun)
    {
        // xor inBuf with iv
        xor(&inBuf, &iv);
        (*firstRun)--;
    }
    else
    {
        // xor with previous ciphertext
        xor(&inBuf, &prevCipherIn);
    }
    
}
