#include "../inc/aes.h"
#include "../inc/key.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COMP_MAX_LEN 10



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



// go through input
// look for markers (-e, -K, -iv)
// check input and output files
// check argument legality (key length / iv length)

/*
 * args             - the command line input
 * inputFilename    - the input filename
 * outputFilename   - the output filename
 * mode             - 0 for encryption, 1 for decryption
 * keySchedule      - the key schedule that will be used for encryption
 * iv               - the iv that will be used for encryption
 */
int parseInput(int argc, char** argv, int* mode, key_t** key, uint8_t** iv, char** inputFilename, char** outputFilename) {

    int encryptionMode = 0;
    int ivInputLength = 0;
    int keyInputLength = 0;
    int addToKeyWords = 7;      
    int keyIndex = 0;      
    int keyPieceBit = 0;     
    uint32_t keyPiece = 0;  
    int ivPieceBit = 0;    
    uint8_t ivPiece = 0;

    
    

    // ./<filename> -e -aes-cbc -K <key> -iv <iv> -in <inputfile> -out <outputfile>

    if (argc < 7)
    {
        printf("Not enough arguments!\n");
        return -1;
    }

    if (strncmp(argv[1], "-e", COMP_MAX_LEN) == 0)
    {
        *mode = 0;
    }
    else if (strncmp(argv[1], "-d", COMP_MAX_LEN) == 0)
    {
       *mode = 1;
    }
    else
    {
        printf("Illegal mode! \"-e\" or \"-d\" modes only!\n");
        return -1;
    }

    if (strncmp(argv[3], "-K", COMP_MAX_LEN) == 0)
    {

        (*key) = malloc(sizeof(key_t));
        if (!(*key))
        {
            printf("Unable to allocate key structure!\n");
            return -1;
        }

        keyInputLength = strnlen(argv[4], 64); // determine key length of input

        if (keyInputLength * 4 == 128)
        {

            (*key)->keyWords = malloc(sizeof(uint128_t));
            if (!(*key)->keyWords)
            {
                printf("Unable to allocate space for 128 bit key!\n");
                return -1;
            }
            (*key)->numRounds = AES_128_NUM_ROUNDS;
            (*key)->keyCanonLength = AES_128_KEY_LENGTH_WORDS;
            (*key)->RconArraySize = 10;
            
        }
        else if (keyInputLength * 4 == 192)
        {

            (*key)->keyWords = malloc(sizeof(uint192_t));
            if (!(*key)->keyWords)
            {
                printf("Unable to allocate space for 192 bit key!\n");
                return -1;
            }
            (*key)->numRounds = AES_192_NUM_ROUNDS;
            (*key)->keyCanonLength = AES_192_KEY_LENGTH_WORDS;
            (*key)->RconArraySize = 8;

        }
        else if (keyInputLength * 4 == 256)
        {

            (*key)->keyWords = malloc(sizeof(uint256_t));
            if (!(*key)->keyWords)
            {
                printf("Unable to allocate space for 256 bit key!\n");
                return -1;
            }
            (*key)->numRounds = AES_256_NUM_ROUNDS;
            (*key)->keyCanonLength = AES_256_KEY_LENGTH_WORDS;
            (*key)->RconArraySize = 7;

        }
        else
        {
            printf("Invalid key length! Keys must be of size 128, 192, or 256 bits!");
            return -1;
        }

        for (int i = 0; i < keyInputLength; i++) // check that key contains legal data
        {

            keyPieceBit = characterToHex(argv[4][i]);

            if (keyPieceBit == -1)
            {
                printf("Illegal character! Key can only use 0123456789ABCDEF!\n");
                return -1;
            }
            
            if (addToKeyWords == 0) // build and add to keyWords
            {

                keyPiece = keyPiece | (keyPieceBit << ((addToKeyWords) * 4)); // add final piece to key word
                (*key)->keyWords[keyIndex] = keyPiece; // add word to key array
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
    else 
    {
        printf("-K needed\n");
        return -1;
    }



    if (strncmp(argv[2], "-aes-ecb", COMP_MAX_LEN) == 0)
    {

        if (strncmp(argv[5], "-in", COMP_MAX_LEN) == 0 && strncmp(argv[7], "-out", COMP_MAX_LEN) == 0)
        {
            *inputFilename = argv[6];
            *outputFilename = argv[8];

            return encryptionMode;
        }

    }
    else if (strncmp(argv[5], "-iv", COMP_MAX_LEN) == 0)
    {

        if (strncmp(argv[2], "-aes-cbc", COMP_MAX_LEN) == 0)
        {
            encryptionMode = 1;
        }
        else if (strncmp(argv[2], "-aes-gcm", COMP_MAX_LEN) == 0)
        {
            encryptionMode = 2;
        }
        else
        {
            return -1;
        }

        

        // get iv 
        *iv = malloc(BUFFER_SIZE * sizeof(uint8_t));
        if (!(*iv))
        {
            printf("Unable to allocate IV!\n");
            return -1;
        }

        ivInputLength = strnlen(argv[6], 64);

        if (ivInputLength != BUFFER_SIZE * 2)
        {
            printf("Incorrect iv size! Must be 16 bytes!\n");
            return -1;
        }

        for (int i = 0; i < ivInputLength; i++)
        {

            ivPieceBit = characterToHex(argv[6][i]);

            if (ivPieceBit == -1)
            {
                printf("Illegal character! Key can only use 0123456789ABCDEF!\n");
                return -1;
            }

            if ((i + 1) % 2 == 0)
            {

                ivPiece |= ivPieceBit << 4;

               
                (*iv)[i / 2] = ivPiece;
                ivPiece = 0;

            }
            else
            {
                ivPiece = ivPieceBit;
            }
            
        }



        // get input filename
        // get output filename
        if (strncmp(argv[7], "-in", COMP_MAX_LEN) == 0 && strncmp(argv[9], "-out", COMP_MAX_LEN) == 0)
        {
            *inputFilename = argv[8];
            *outputFilename = argv[10];

            return encryptionMode;
        }

    }   

    return -1;

}
