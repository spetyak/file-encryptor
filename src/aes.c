#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../inc/key.h"
#include "../inc/encrypt.h"
#include "../inc/decrypt.h"

// ********************************************************************************
// CONSTANTS
// ********************************************************************************

#define BUFFER_SIZE 16                  // 16 bytes (since block length is 16 bytes)
#define BLOCK_SIZE_BYTES 16             // block length is fixed at 128 bits or 16 bytes
#define AES_NUM_BLOCKS 4                // 
#define WORD_SIZE_BYTES 4               // a word is 4 bytes
#define BLOCK_ROW_COL_SIZE 4            // the block represented by a matrix is 4 bytes x 4 bytes
#define AES_128_KEY_LENGTH 128          // the number of bits in an AES-128 key
#define AES_192_KEY_LENGTH 192          // the number of bits in an AES-192 key
#define AES_256_KEY_LENGTH 256          // the number of bits in an AES-256 key
#define AES_128_KEY_LENGTH_WORDS 4      // the number of words in a key for a key length of 128 is 4
#define AES_192_KEY_LENGTH_WORDS 6      // the number of words in a key for a key length of 192 is 6
#define AES_256_KEY_LENGTH_WORDS 8      // the number of words in a key for a key length of 256 is 8
#define AES_128_NUM_ROUNDS 10           // the number of rounds for AES-128 is 10
#define AES_192_NUM_ROUNDS 12           // the number of rounds for AES-192 is 12
#define AES_256_NUM_ROUNDS 14           // the number of rounds for AES-256 is 14



// AES-128:
    //      keyWordLength   = 4 words       = 16 bytes
    //      blockSize       = 4 words       = 16 bytes
    //      numRounds       = 10 rounds

    // AES-192:
    //      keyWordLength   = 6 words       = 24 bytes
    //      blockSize       = 4 words       = 16 bytes
    //      numRounds       = 12 rounds

    // AES-256:
    //      keyWordLength   = 8 words       = 32 bytes
    //      blockSize       = 4 words       = 16 bytes
    //      numRounds       = 14 rounds



// ********************************************************************************
// GLOBALS
// ********************************************************************************

FILE *ptread, *ptwrite;
uint8_t* Rcon = NULL;
uint32_t* keySchedule = NULL;
uint32_t* keyWords = NULL;



// ********************************************************************************
// PROTOTYPES
// ********************************************************************************



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

    int scheduleLength = (keyLengthInWords * (numRounds + 1)); 

    // allocate space for key schedule array
    keySchedule = malloc(sizeof(uint32_t) * scheduleLength);
    if (!keySchedule)
    {
        printf("Allocation of key schedule failed!\n");
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
            // printf("Rcon: %X\n", Rcon[(i / keyLengthInWords) - 1]);



            //      From Fig. 11, it can be seen that the first <keyWordLength> words of the expanded key are filled with the
            // Cipher Key. Every following word, w[i], is equal to the XOR of the previous word, w[i-1], 
            // and the word <keyWordLength> positions earlier, w[i - keyWordLength]. 
            // For words in positions that are a multiple of <keyWordLength>, a transformation is applied to 
            // w[i-1] prior to the XOR, followed by an XOR with a round constant, Rcon[i]. This transformation 
            // consists of a cyclic shift of the bytes in a word (RotWord()), followed by the application 
            // of a table lookup to all four bytes of the word (SubWord()).
            // 
            //      It is important to note that the Key Expansion routine for 256-bit Cipher Keys (keyWordLength = 8) is
            // slightly different than for 128- and 192-bit Cipher Keys. If keyWordLength = 8 and i-4 is a multiple of keyWordLength,
            // then SubWord() is applied to w[i-1] prior to the XOR. 

            

            if (keyLengthInWords == AES_256_KEY_LENGTH_WORDS && ((i - 4) % keyLengthInWords == 0))
            {

                // transformation applied to previous word w[i-1]
                // XOR with round constant Rcon

                keySchedule[i] = (subWord(rotWord(keySchedule[i-1])) ^ roundConstant) ^ keySchedule[i - keyLengthInWords]; 

            }
            else if ((i - keyLengthInWords) % keyLengthInWords == 0)
            {

                uint32_t afterRotWord = rotWord(keySchedule[i-1]);
                uint32_t afterSubWord = subWord(afterRotWord);
                uint32_t afterXORRcon = afterSubWord ^ roundConstant;
                uint32_t wink = keySchedule[i - keyLengthInWords];
                uint32_t tempXORwink = (afterXORRcon) ^ (wink);
                keySchedule[i] = tempXORwink;

            }
            else
            {
                keySchedule[i] = keySchedule[i-1] ^ keySchedule[i - keyLengthInWords];
            }

        }

        // printf("Key schedule %3d: %X\n", i, keySchedule[i]);
        
    }

}



void addRoundKey(uint8_t* block, int round) {
    
    int l = round * AES_NUM_BLOCKS; // l = Round * blockSize

    for (int i = 0; i < BLOCK_ROW_COL_SIZE; i++)
    {

        uint8_t k1 = (keySchedule[l + i] & (0xFF << 24)) >> 24;
        uint8_t k2 = (keySchedule[l + i] & (0xFF << 16)) >> 16;
        uint8_t k3 = (keySchedule[l + i] & (0xFF << 8)) >> 8;
        uint8_t k4 = keySchedule[l + i]; 

        block[i] ^= k1; // 0 xor 0
        block[(4 * 1) + i] ^= k2; // 1 xor 1
        block[(4 * 2) + i] ^= k3; // 2 xor 2
        block[(4 * 3) + i] ^= k4; // 3 xor 3

    }

}



int characterToHex(char c) {

    switch (c) {

        case '0':
            return 0;
        case '1':
            return 1;
        case '2':
            return 2;
        case '3':
            return 3;
        case '4':
            return 4;
        case '5':
            return 5;
        case '6':
            return 6;
        case '7':
            return 7;
        case '8':
            return 8;
        case '9':
            return 9;
        case 'A':
            return 0xA;
        case 'B':
            return 0xB;
        case 'C':
            return 0xC;
        case 'D':
            return 0xD;
        case 'E':
            return 0xE;
        case 'F':
            return 0xF;
        default:
            return -1;

    }

}



void createRoundConstantArray(uint8_t* Rcon, int RconLength) {

    for (int i = 0; i < RconLength; i++)
    {

        if (i == 0)
        {
            Rcon[i] = 1;
        }
        else if (i > 0 && Rcon[i-1] < 0x80)
        {
            Rcon[i] = 2 * Rcon[i-1];
        }
        else
        {
            Rcon[i] = (2 * Rcon[i-1]) ^ 0x11B;
        }

    }

}



void swapRowsAndColumns(uint8_t* block) {

    // swap rows and columns
    uint8_t swap[16] = {0};
    for (int i = 0; i < BLOCK_ROW_COL_SIZE; i++)
    {

        for (int j = 0; j < BLOCK_ROW_COL_SIZE; j++)
        {

            swap[(4 * i) + j] = block[i + (4 * j)]; 

        }

    }
    
    for (int i = 0; i < BUFFER_SIZE; i++)
    {
        block[i] = swap[i];
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

    // if keyWords was allocated (not NULL), free it
    if (keyWords) {
        free(keyWords);
    }

    // if Rcon was allocated (not NULL), free it
    if (Rcon) {
        free(Rcon);
    }

    // if keySchedule was allocated (not NULL), free it
    if (keySchedule) {
        free(keySchedule);
    }

}





int main(int argc, char** argv) {

    // add algorithm

    // read in plaintext 
    // L read in 16 bytes at a time

    // FILE *ptread, *ptwrite;

    uint8_t inBuf[BUFFER_SIZE] = {0};
    uint8_t inputByte[1] = {0};

    char* inputFilename = NULL;
    char* outputFilename = NULL;
    int keyCanonLength = 0;
    int keyInputLength = 0;
    int RconArraySize = 0;
    // uint32_t* keyWords = NULL;
    uint128_t* key = NULL;
    int numRounds = 0;
    int addToKeyWords = 7;
    int keyIndex = 0;
    uint32_t keyPiece = 0;
    int mode = 0;

    // will eventually want to change this to check for 5 args (current args plus -e or -d)
    if (argc == 6) // the user provided 4 arguments (./<filename> -e -K <key> <inputfile> <outputfile>)
    {
        
        if (strncmp(argv[2], "-K", 2) == 0) // if we are provided a flag indicating a key...
        {

            keyInputLength = strnlen(argv[3], 32); // determine key length of input

            printf("key length: %d\n", keyInputLength * 4);

        

            if (keyInputLength * 4 == 128)
            {

                key = malloc(sizeof(uint128_t));
                if (!key)
                {
                    printf("Unable to allocate space for 128 bit key!\n");
                    exit(-1);
                }
                keyWords = key->w;
                numRounds = AES_128_NUM_ROUNDS;
                keyCanonLength = AES_128_KEY_LENGTH_WORDS;
                RconArraySize = 10;
                
            }
            else if (keyInputLength * 4 == 192)
            {

                key = malloc(sizeof(uint192_t));
                if (!key)
                {
                    printf("Unable to allocate space for 192 bit key!\n");
                    exit(-1);
                }
                keyWords = key->w;
                numRounds = AES_192_NUM_ROUNDS;
                keyCanonLength = AES_192_KEY_LENGTH_WORDS;
                RconArraySize = 8;

            }
            else if (keyInputLength * 4 == 256)
            {

                key = malloc(sizeof(uint256_t));
                if (!key)
                {
                    printf("Unable to allocate space for 256 bit key!\n");
                    exit(-1);
                }
                keyWords = key->w;
                numRounds = AES_256_NUM_ROUNDS;
                keyCanonLength = AES_256_KEY_LENGTH_WORDS;
                RconArraySize = 7;

            }
            else
            {
                printf("Invalid key length! Keys must be of size 128, 192, or 256 bits!");
                exit(-1);
            }

            for (int i = 0; i < keyInputLength; i++) // check that key contains legal data
            {

                int keyPieceBit = characterToHex(argv[3][i]);

                if (keyPieceBit == -1)
                {
                    printf("Illegal character! Key can only use 0123456789ABCDEF!\n");
                    exit(-1);
                }
                else
                {

                    if (addToKeyWords == 0) // build and add to keyWords
                    {

                        keyPiece = keyPiece | (keyPieceBit << ((addToKeyWords) * 4)); // add final piece to key word
                        keyWords[keyIndex] = keyPiece; // add word to key array
                        addToKeyWords = 7;
                        keyIndex++; // begin work on next key word 
                        keyPiece = 0; // reset key piece
                        continue;

                    }
                    else // build key word
                    {
                        keyPiece = keyPiece | (keyPieceBit << ((addToKeyWords) * 4)); // add piece to key word
                    }

                    addToKeyWords--;

                }

            }

        }
        else
        {
            // notify user of correct command signature
            printf("error in command sig\n");
            exit(-1);
        }

        if (strncmp(argv[1], "-e", 2) == 0)
        {
            mode = 0;
        }
        else if (strncmp(argv[1], "-d", 2) == 0)
        {
            mode = 1;
        }
        else
        {
            // invalid option!
            printf("Invalid option\n");
        }

        inputFilename = argv[4];
        outputFilename = argv[5];

    }
    else
    {
        printf("Invalid number of arguments!\n");
        exit(-1);
    }

    if ((ptread = fopen(inputFilename, "rb")) == NULL)
    {
        printf("File %s cannot be opened\n", inputFilename);
        exit(-1);
    }

    if ((ptwrite = fopen(outputFilename, "wb")) == NULL)
    {
        printf("File %s cannot be opened\n", outputFilename);
        exit(-1);
    } 
    fseek(ptwrite, 0, SEEK_SET);

    // parse for key
    //      L put words into their respective array spots
    //      L as you are doing so, check that characters are legal byte characters (ie. 0123456789ABCDEF)
    //      L if any other characters are found, exit and display error
    //      L keep track of key length (stop if greater than 256)
    //              L actual character lengths are as follows:
    //              L 128 bit key   =   32 characters   (bytes are represented by 2 characters, and there are 16 bytes)
    //              L 192 bit key   =   48 characters   (bytes are represented by 2 characters, and there are 24 bytes)
    //              L 256 bit key   =   64 characters   (bytes are represented by 2 characters, and there are 32 bytes)

    // look for -K and the input following immediately after



    // create round constants
    Rcon = malloc(sizeof(uint8_t) * RconArraySize);
    if (Rcon == NULL)
    {
        printf("Unable to allocate round constant array!\n");
        exit(-1);
    }

    createRoundConstantArray(Rcon, RconArraySize);

    // expand given key
    createKeySchedule(keyWords, keyCanonLength, numRounds);


    

    // put input in this order:
    // 0  4  8 12
    // 1  5  9 13
    // 2  6 10 14
    // 3  7 11 15

    

    if (0 != fread(inBuf, sizeof(uint8_t), BUFFER_SIZE, ptread)) // read in 16 bytes
    {
        swapRowsAndColumns(inBuf);
    }
    else
    {
        printf("Nothing was read!\n");
        cleanup();
        exit(-1);
    }
    


    printf("Before: %s\n", inBuf);
    printf("buf contents before: 0x");
    for (int i = 0; i < BUFFER_SIZE; i++)
    {
        printf("%2X", inBuf[i]);
    }
    printf("\n");
    

    if (mode == 0) // encrypt
    {

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
    else // decrypt
    {

        addRoundKey(inBuf, 0); // add roundkey (add cipher key to ciphertext)

        for (int i = 1; i < numRounds-1; i++)
        {
            invShiftRows(inBuf);
            invSubBytes(inBuf);
            invMixColumns(inBuf);
            addRoundKey(inBuf, i);
            
        }

        invShiftRows(inBuf);
        invSubBytes(inBuf);
        
        addRoundKey(inBuf, numRounds);

    }



    swapRowsAndColumns(inBuf);

    printf("Writing %lu thing(s) of size %d to output\n", sizeof(uint8_t), BUFFER_SIZE);

    // write encrypted buffer to output file (append that is)
    //      L actually shouldn't we write over the block we just processed? (if output file is same as input)
    fwrite(inBuf, sizeof(uint8_t), BUFFER_SIZE, ptwrite);
        
    

    printf("After: %s\n", inBuf);
    printf("buf contents after: 0x");
    for (int i = 0; i < BUFFER_SIZE; i++)
    {
        printf("%2X", inBuf[i]);
    }
    printf("\n");

    
    
    memset(inBuf, 0, BUFFER_SIZE); // reset buffer to prevent repeats when EOF reached

    // }



    // fclose(ptwrite);
    // fclose(ptread);
    // free(keyWords);
    // free(Rcon);
    // free(keySchedule);
    cleanup();

    return 0;

}
