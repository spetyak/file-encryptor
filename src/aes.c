#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#include "../inc/aes.h"
#include "../inc/key.h"
#include "../inc/parse.h"
#include "../inc/encrypt.h"
#include "../inc/decrypt.h"
#include "../inc/cbc.h"



// ********************************************************************************
// GLOBALS
// ********************************************************************************

FILE *ptread = NULL;            // read file pointer
FILE *ptwrite = NULL;           // write file pointer
key_t* key = NULL;              // 
uint8_t* iv = NULL;             // 
uint8_t* Rcon = NULL;           // round constant array
uint32_t* keySchedule = NULL;   // key schedule array
uint32_t* keyWords = NULL;      // array of words that make up key



// ********************************************************************************
// FUNCTIONS
// ********************************************************************************



/**
 * Substitutes the bytes in the the input word using the s-box
 */
uint32_t subWord(uint32_t word) {

    int32_t newWord = 0;

    // apply sbox to bytes in word
    for (int i = 0; i < WORD_SIZE_BYTES; i++)
    {

        uint32_t byte_to_sub = (word & (0xFF << (i * 8))) >> (i * 8);
        newWord |= subByte(byte_to_sub) << (i * 8); // add substituted byte to word

    }

    return newWord;

}

/**
 * Performs a cyclic permutation
 */
uint32_t rotWord(uint32_t word) {

    uint32_t temp = (word & (0xFF << 24)) >> 24; // grab first byte to move to end
    word <<= 8; // shift rest down
    word |= temp; // put first byte at end

    return word;

}

/**
 * Create the key schedule for the encryption rounds.
 * Generates BLOCK_SIZE * (numRounds + 1) words used as round keys.
 */
void createKeySchedule(uint32_t* key, int keyLengthInWords, int numRounds) {

    // RESULT: array of 4 byte (ex. key = 0x12345678) keys
    //          L array will be of size blockSize * (numRounds + 1)
    //                                  4 bytes * (16 * (numRounds + 1))

    int scheduleLength = (AES_BLOCK_SIZE_WORDS * (numRounds + 1)); 

    // allocate space for key schedule array
    keySchedule = malloc(sizeof(uint32_t) * scheduleLength);
    if (!keySchedule)
    {
        printf("Allocation of key schedule failed!\n");
        cleanup();
        exit(-1);
    }

    
    for (int i = 0; i < scheduleLength; i++)
    {

        // w[i] with index 0 to keyLengthInWords are just filled with the base key
        if (i < keyLengthInWords)
        {
            keySchedule[i] = key[i];
        }
        else
        {

            // The round constant word array, Rcon[i], contains 
            // the values given by [x^(i-1),{00},{00},{00}], with x^(i-1) being powers of x 
            // (x is denoted as {02}) in the field GF(2^8), as discussed in Sec. 4.2 (note that i starts at 1, not 0).

            uint32_t roundConstant = Rcon[(i / keyLengthInWords) - 1] << (3 * 8);

            

            if (keyLengthInWords == AES_256_KEY_LENGTH_WORDS && ((i - 4) % keyLengthInWords == 0))
            {
                keySchedule[i] = subWord(keySchedule[i-1]) ^ keySchedule[i - keyLengthInWords];
            }
            else if ((i - keyLengthInWords) % keyLengthInWords == 0)
            {
                keySchedule[i] = (subWord(rotWord(keySchedule[i-1])) ^ roundConstant) ^ keySchedule[i - keyLengthInWords];
            }
            else
            {
                keySchedule[i] = keySchedule[i-1] ^ keySchedule[i - keyLengthInWords];
            }

        }

        // printf("key schedule %3d: 0x%X\n", i, keySchedule[i]);
        
    }

}



void addRoundKey(uint8_t* block, int round) {
    
    int l = round * AES_BLOCK_SIZE_WORDS; // l = Round * blockSize

    for (int i = 0; i < BLOCK_ROW_COL_SIZE; i++)
    {

        uint8_t k1 = (keySchedule[l + i] & (0xFF << 24)) >> 24;
        uint8_t k2 = (keySchedule[l + i] & (0xFF << 16)) >> 16;
        uint8_t k3 = (keySchedule[l + i] & (0xFF << 8)) >> 8;
        uint8_t k4 = keySchedule[l + i] & 0xFF; 

        block[i] ^= k1;
        block[(4 * 1) + i] ^= k2;
        block[(4 * 2) + i] ^= k3;
        block[(4 * 3) + i] ^= k4; 

    }

}



void createRoundConstantArray(int RconArraySize) {

    Rcon = malloc(sizeof(uint8_t) * RconArraySize);
    if (Rcon == NULL)
    {
        printf("Unable to allocate round constant array!\n");
        cleanup();
        exit(-1);
    }

    for (int i = 0; i < RconArraySize; i++)
    {

        if (i == 0)
        {
            Rcon[i] = 1;
        }
        else if (i > 0 && Rcon[i-1] < 0x80)
        {
            Rcon[i] = Rcon[i-1] << 1;
        }
        else
        {
            Rcon[i] = (Rcon[i-1] << 1) ^ 0x11B;
        }

    }

}



void swapRowsAndColumns(uint8_t* block) {

    for (int i = 0; i < BLOCK_ROW_COL_SIZE; i++)
    {

        for (int j = i; j < BLOCK_ROW_COL_SIZE; j++)
        {

            uint8_t temp = block[(4 * i) + j];          
            block[(4 * i) + j] = block[(4 * j) + i];
            block[(4 * j) + i] = temp;

        }

    }

}



void cleanup() {

    // if ptread open (not NULL), close it
    if (ptread) {
        fclose(ptread);
    }

    // if ptwrite open (not NULL), close it
    if (ptwrite) {
        fclose(ptwrite);
    }

    // if Rcon was allocated (not NULL), free it
    if (Rcon) {
        free(Rcon);
    }

    // if keySchedule was allocated (not NULL), free it
    if (keySchedule) {
        free(keySchedule);
    }

    if (key) {

        if (key->keyWords) {
            free(key->keyWords);
        }

        free(key);

    }

}



void aesEncrypt(uint8_t* inBuf, int numRounds) {

    addRoundKey(inBuf, 0); // add roundkey (add cipher key to plaintext)

    for (int i = 1; i < numRounds; i++)
    {

        subBytes(inBuf);
        shiftRows(inBuf);
        mixColumns(inBuf);
        addRoundKey(inBuf, i);

    }

    subBytes(inBuf); // subBytes
    shiftRows(inBuf); // shiftRows
    addRoundKey(inBuf, numRounds); // addRoundKey

}

void aesDecrypt(uint8_t* inBuf, int numRounds) {

    // decryption starts at numRounds and works back down

    addRoundKey(inBuf, numRounds); 

    for (int i = numRounds-1; i > 0; i--)
    {
        invShiftRows(inBuf);
        invSubBytes(inBuf);
        addRoundKey(inBuf, i);
        invMixColumns(inBuf);
        
    }

    invShiftRows(inBuf);
    invSubBytes(inBuf);
    addRoundKey(inBuf, 0);
    
}





int main(int argc, char** argv) {

    uint8_t inBuf[BUFFER_SIZE] = {0}; // file input
    uint8_t prevCipherOut[BUFFER_SIZE] = {0};
    uint8_t prevCipherIn[BUFFER_SIZE] = {0};

    char* inputFilename = NULL; // input filename pointer
    char* outputFilename = NULL; // output filename pointer
    int mode = 0;               // 0 for encryption, 1 for decryption
    int firstRun = 1;           // used for CBC encryption to determine what to XOR the input with
    

    int encryptionMode = parseInput(argc, argv, &mode, &key, &iv, &inputFilename, &outputFilename);

    if (encryptionMode == -1) // an error occurred when parsing userInput (either by fault of user or system)
    {
        // error message cause is displayed by parse.c 
        cleanup();
        exit(-1);
    }





    if ((ptread = fopen(inputFilename, "rb")) == NULL)
    {
        printf("File %s cannot be opened\n", inputFilename);
        cleanup();
        exit(-1);
    }

    if ((ptwrite = fopen(outputFilename, "wb")) == NULL)
    {
        printf("File %s cannot be opened\n", outputFilename);
        cleanup();
        exit(-1);
    } 
    fseek(ptread, 0, SEEK_END);
    unsigned long fileSize = ftell(ptread);
    printf("File size: %lu\n", fileSize);
    fseek(ptread, 0, SEEK_SET);
    fseek(ptwrite, 0, SEEK_SET); // move write pointer to beginning of file


    
    createRoundConstantArray(key->RconArraySize); // create round constants array
    createKeySchedule(key->keyWords, key->keyCanonLength, key->numRounds); // expand given key

    if (encryptionMode == 0) {
        printf("USING ECB MODE!\n");
    }
    else if (encryptionMode == 1) {
        printf("USING CBC MODE!\n");
    }
    else if (encryptionMode == 2) {
        printf("USING GCM MODE!\n");
    }



    // printf("Progress:\n");



    float startTime = (float) clock() / CLOCKS_PER_SEC;

    while (fread(inBuf, sizeof(uint8_t), BUFFER_SIZE, ptread) != 0) // READ FROM INPUT FILE
    {

        // printf("\r%lu / %lu", ftell(ptread), fileSize);

        swapRowsAndColumns(inBuf);

        if (encryptionMode == 0) // AES-ECB
        {

            // just simply use AES encryption/decryption functions
            // no need to hold on to generated output
            if (mode == 0) {
                aesEncrypt(inBuf, key->numRounds);
            }
            else {
                aesDecrypt(inBuf, key->numRounds);
            }

        }
        else 
        {

            swapRowsAndColumns(iv);

            if (encryptionMode == 1) // AES-CBC
            {

                if (mode == 0) {
                    cbcEncrypt(inBuf, prevCipherOut, prevCipherIn, key->numRounds, iv, &firstRun);
                }
                else {
                    cbcDecrypt(inBuf, prevCipherOut, prevCipherIn, key->numRounds, iv, &firstRun);
                }

                memcpy(prevCipherIn, prevCipherOut, BUFFER_SIZE);

            }
            else if (encryptionMode == 2)// AES-GCM
            {

                if (mode == 0) {

                }
                else {

                }
                
            }

            swapRowsAndColumns(iv);

        }

        swapRowsAndColumns(inBuf);


        
        fwrite(inBuf, sizeof(uint8_t), BUFFER_SIZE, ptwrite);// WRITE TO OUTPUT FILE

        memset(inBuf, 0, BUFFER_SIZE);

    }


    float endTime = (float) clock()/CLOCKS_PER_SEC;

    printf("\nTime to en/de-crypt %lu bytes : %fs\n", fileSize, endTime-startTime);


    cleanup();

    // system("leaks aes"); // used to check for memory leaks

    return 0;

}
