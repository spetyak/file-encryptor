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



// /* Substitution box */
// static const uint8_t sbox[256] = 
// {
//     0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
//     0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
//     0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
//     0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
//     0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
//     0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
//     0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
//     0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
//     0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
//     0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
//     0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
//     0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
//     0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
//     0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
//     0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
//     0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
// };


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


// /**
//  * Substitute the input byte using s-box
//  */
// uint8_t subByte(uint8_t inputByte) {

//     // printf("Input: %X\n", inputByte);

//     uint8_t MSB = (inputByte & 0xF0) >> 4; // 0xF-
//     uint8_t LSB = (inputByte & 0xF);      // 0x-F

//     // printf("MSB: %X, LSB: %X\n", MSB, LSB);

//     return sbox[(16 * MSB) + LSB]; 

// }

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

        printf("Key schedule %3d: %X\n", i, keySchedule[i]);
        
    }

}



// void subBytes(uint8_t* block) {

//     for (int i = 0; i < BUFFER_SIZE; i++)
//     {
//         block[i] = subByte(block[i]);
//     }

// }

// void shiftRows(uint8_t* block) {

//     for (int i = 0; i < BLOCK_ROW_COL_SIZE; i++)
//     {

//         // 0, don't shift
//         // 1, shift left once
//         // 2, shift left twice
//         // 3, shift left 3 times

//         for (int j = 0; j < i; j++)
//         {

//             int8_t temp = block[BLOCK_ROW_COL_SIZE * i];
//             block[BLOCK_ROW_COL_SIZE * i] = block[(BLOCK_ROW_COL_SIZE * i) + 1];
//             block[(BLOCK_ROW_COL_SIZE * i) + 1] = block[(BLOCK_ROW_COL_SIZE * i) + 2];
//             block[(BLOCK_ROW_COL_SIZE * i) + 2] = block[(BLOCK_ROW_COL_SIZE * i) + 3];
//             block[(BLOCK_ROW_COL_SIZE * i) + 3] = temp;

//         }

//     }

// }

// void mixColumns(uint8_t* block) {

//     uint8_t a[16] =
//     {
//         0x02, 0x03, 0x01, 0x01,
//         0x01, 0x02, 0x03, 0x01,
//         0x01, 0x01, 0x02, 0x03,
//         0x03, 0x01, 0x01, 0x02
//     };

//     for (int i = 0; i < BLOCK_ROW_COL_SIZE; i++)
//     {

//         uint8_t r1 = block[(BLOCK_ROW_COL_SIZE * 0) + i];
//         uint8_t r2 = block[(BLOCK_ROW_COL_SIZE * 1) + i];
//         uint8_t r3 = block[(BLOCK_ROW_COL_SIZE * 2) + i];
//         uint8_t r4 = block[(BLOCK_ROW_COL_SIZE * 3) + i];

//         for (int j = 0; i < BLOCK_ROW_COL_SIZE; i++)
//         {

//             uint8_t a1 = a[(BLOCK_ROW_COL_SIZE * j) + 0];
//             uint8_t a2 = a[(BLOCK_ROW_COL_SIZE * j) + 1];
//             uint8_t a3 = a[(BLOCK_ROW_COL_SIZE * j) + 2];
//             uint8_t a4 = a[(BLOCK_ROW_COL_SIZE * j) + 3];

//             block[(BLOCK_ROW_COL_SIZE * j) + i] = (r1 * a1) ^ (r2 * a2) ^ (r3 * a3) ^ (r4 * a4);

//         }

//     }

// }



void addRoundKey(uint8_t* block, int round) {
    
    int l = round * AES_NUM_BLOCKS; // l = Round * blockSize

    for (int i = 0; i < BLOCK_ROW_COL_SIZE; i++)
    {

        // 0  1  2  3
        // 4  5  6  7
        // 8  9  10 11
        // 12 13 14 15

        // XOR block columns with key schedule column

        block[i] ^= keySchedule[l + 0]; // 0 xor 0
        block[4 + i] ^= keySchedule[l + 1]; // 1 xor 1
        block[8 + i] ^= keySchedule[l + 2]; // 2 xor 2
        block[12 + i] ^= keySchedule[l + 3]; // 3 xor 3

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

    char* filename = NULL;
    int keyCanonLength = 0;
    int keyInputLength = 0;
    int RconArraySize = 0;
    // uint32_t* keyWords = NULL;
    uint128_t* key = NULL;
    int numRounds = 0;
    int addToKeyWords = 7;
    int keyIndex = 0;
    uint32_t keyPiece = 0;

    // will eventually want to change this to check for 5 args (current args plus -e or -d)
    if (argc == 4) // the user provided 4 arguments (./<filename> -K <key> <inputfile>)
    {
        
        if (strncmp(argv[1], "-K", 2) == 0) // if we are provided a flag indicating a key...
        {

            keyInputLength = strnlen(argv[2], 32); // determine key length of input

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

                int keyPieceBit = characterToHex(argv[2][i]);

                if (keyPieceBit == -1)
                {
                    printf("Illegal character! Key can only use 0123456789ABCDEF!\n");
                    exit(-1);
                }
                else
                {

                    // printf("Shifting by %d\n", addToKeyWords * 4);
                    // printf("Val: %X\n", keyPieceBit << ((addToKeyWords) * 4));

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

        filename = argv[3];

    }
    else
    {
        printf("Invalid number of arguments!\n");
        exit(-1);
    }

    if ((ptread = fopen(filename, "r")) == NULL)
    {
        printf("File %s cannot be opened\n", filename);
        exit(-1);
    }

    if ((ptwrite = fopen("output.txt", "w")) == NULL)
    {
        printf("File %s cannot be opened\n", "output.txt");
        exit(-1);
    } 

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


    


    // parse through input file
    while (feof(ptread) == 0)
    {
        if (0 != fread(inBuf, sizeof(uint8_t), BUFFER_SIZE, ptread))
        {

            printf("something was read\n");
            
            // perform round operations:
            // L sub-bytes
            // L shift rows
            // L mix columns
            // L add round key

            addRoundKey(inBuf, 0); // add roundkey (add cipher key to plaintext)

            for (int i = 1; i < numRounds-1; i++)
            {

                subBytes(inBuf);
                shiftRows(inBuf);
                mixColumns(inBuf);
                addRoundKey(inBuf, i);

            }

            subBytes(inBuf); // subBytes
            shiftRows(inBuf); // shiftRows
            addRoundKey(inBuf, numRounds); // addRoundKey





            printf("Writing %lu thing(s) of size %d to output\n", sizeof(uint8_t), BUFFER_SIZE);

            // write encrypted buffer to output file (append that is)
            //      L actually shouldn't we write over the block we just processed? (if output file is same as input)
            fwrite(inBuf, sizeof(uint8_t), BUFFER_SIZE, ptwrite);
            
        }

        
        
        memset(inBuf, 0, BUFFER_SIZE); // reset buffer to prevent repeats when EOF reached

    }



    // fclose(ptwrite);
    // fclose(ptread);
    // free(keyWords);
    // free(Rcon);
    // free(keySchedule);
    cleanup();

    return 0;

}
