#include "../inc/aes.h"
#include "../inc/key.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COMP_MAX_LEN 128



/*
 * Converts user input character into a nibble to be used as part of a key/iv.
 *
 * c    - the user character given to represent half of a byte of the given key/iv
 */
int characterToHex(char c) {

    if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
    {
        return c;
    }
    else if (c >= 'a' && c <= 'z')
    {
        return (c - 0x20);
    }
    else
    {
        return -1;
    }

}



/*
 * Takes user input in order to build the components necessary for encryption/decryption.
 *
 * args             - the command line input
 * inputFilename    - the input filename
 * outputFilename   - the output filename
 * mode             - 0 for encryption, 1 for decryption
 * keySchedule      - the key schedule that will be used for encryption
 * iv               - the iv that will be used for encryption
 */
int parseInput(int* mode, myKey_t** key, uint8_t** iv, char** inputFilename, char** outputFilename) {

    char* userInput = NULL;     // pointer for user input
    size_t size = 0;            // returned size of user input

    int encryptionMode = 0;     // 0 for ECB encryption, 1 for CBC encryption, 2 for GCM encryption
    int ivInputLength = 0;      // the length of the user input for the iv
    int keyInputLength = 0;     // the length of the user input for the key
    int keyWordIndex = 0;       // counter used to help build key words
    int keyIndex = 0;           // index of current keyword being made
    int keyWordNibble = 0;      // current 4 bits being added to keyword 
    uint32_t keyWord = 0;       // current word of the key being built
    int ivPieceNibble = 0;      // current 4 bits being added to iv
    uint8_t ivPiece = 0;        // current iv word being built



    // CHOOSE ENCRYPTION OR DECRYPTION
    printf("Would you like to ENCRYPT (0) or DECRYPT (1)?: ");
    getline(&userInput, &size, stdin);
    sscanf(userInput, "%d", &(*mode));



    // GET INPUT/OUTPUT FILEPATH
    *inputFilename = malloc(150 * sizeof(char));
    if (!(*inputFilename))
    {
        printf("Failed to allocate input filename!\n");
        return -1;
    }
    *outputFilename = malloc(150 * sizeof(char));
    if (!(*outputFilename))
    {
        printf("Failed to allocate output filename!\n");
        return -1;
    }

    printf("Input file path: ");
    getline(inputFilename, &size, stdin);
    sscanf(*inputFilename, "%[^\n]", *inputFilename);

    printf("Output file path: ");
    getline(outputFilename, &size, stdin);
    sscanf(*outputFilename, "%[^\n]", *outputFilename);



    // GET MODE (0 for ECB, 1 for CBC, 2 for GCM)
    printf("Please choose an encryption mode.\n");
    printf("ECB(0), CBC(1), or GCM(2): ");
    getline(&userInput, &size, stdin);
    sscanf(userInput, "%d", &encryptionMode);



    // GET KEY
    printf("Key: ");
    getline(&userInput, &size, stdin);
    sscanf(userInput, "%[^\n]", userInput);
    
    (*key) = malloc(sizeof(myKey_t));
    if (!(*key))
    {
        printf("Unable to allocate key structure!\n");
        return -1;
    }

    keyInputLength = strnlen(userInput, COMP_MAX_LEN); // determine key length of input

    if (keyInputLength * 4 == 128)
    {

        printf("Using AES-128\n");

        (*key)->keyWords = malloc(sizeof(uint128_t));
        if (!(*key)->keyWords)
        {
            printf("Unable to allocate space for 128 bit key!\n");
            return -1;
        }
        (*key)->numRounds = AES_128_NUM_ROUNDS;
        (*key)->keyLengthInWords = AES_128_KEY_LENGTH_WORDS;
        (*key)->RconArraySize = 10;
        
    }
    else if (keyInputLength * 4 == 192)
    {

        printf("Using AES-192\n");

        (*key)->keyWords = malloc(sizeof(uint192_t));
        if (!(*key)->keyWords)
        {
            printf("Unable to allocate space for 192 bit key!\n");
            return -1;
        }
        (*key)->numRounds = AES_192_NUM_ROUNDS;
        (*key)->keyLengthInWords = AES_192_KEY_LENGTH_WORDS;
        (*key)->RconArraySize = 8;

    }
    else if (keyInputLength * 4 == 256)
    {

        printf("Using AES-256\n");

        (*key)->keyWords = malloc(sizeof(uint256_t));
        if (!(*key)->keyWords)
        {
            printf("Unable to allocate space for 256 bit key!\n");
            return -1;
        }
        (*key)->numRounds = AES_256_NUM_ROUNDS;
        (*key)->keyLengthInWords = AES_256_KEY_LENGTH_WORDS;
        (*key)->RconArraySize = 7;

    }
    else
    {
        printf("Invalid key length! Keys must be of size 128, 192, or 256 bits!\n");
        return -1;
    }

    for (int i = 0; i < keyInputLength; i++) // check that key contains legal data
    {

        keyWordNibble = characterToHex(userInput[i]);

        if (keyWordNibble == -1)
        {
            printf("Illegal character! Key can only use 0123456789ABCDEF!\n");
            return -1;
        }
        
        if (keyWordIndex == 7) // build and add to keyWords
        {

            keyWord = keyWord | (keyWordNibble << ((keyWordIndex) * 4)); // add final piece to key word
            (*key)->keyWords[keyIndex] = keyWord; // add word to key array
            keyWordIndex = 0;
            keyIndex++; // begin work on next key word 
            keyWord = 0; // reset key piece
            continue;

        }
        else // build key word
        {
            keyWord = keyWord | (keyWordNibble << ((keyWordIndex) * 4)); // add piece to key word
        }

        keyWordIndex++;

    }



    // GET IV
    printf("IV: ");
    getline(&userInput, &size, stdin);
    sscanf(userInput, "%[^\n]", userInput);

    ivInputLength = strnlen(userInput, COMP_MAX_LEN);

    if (ivInputLength != BUFFER_SIZE * 2) // confirm IV given contains 16 bytes (should be 32 characters)
    {
        printf("Incorrect iv size! Must be 16 bytes!\n");
        return -1;
    }

    *iv = malloc(BUFFER_SIZE * sizeof(uint8_t));
    if (!(*iv))
    {
        printf("Unable to allocate IV!\n");
        return -1;
    }

    for (int i = 0; i < ivInputLength; i++)
    {

        ivPieceNibble = characterToHex(userInput[i]);

        if (ivPieceNibble == -1)
        {
            printf("Illegal character! Key can only use 0123456789ABCDEF!\n");
            return -1;
        }

        if ((i + 1) % 2 == 0)
        {

            ivPiece = (ivPiece << 4) | ivPieceNibble;

            (*iv)[i / 2] = ivPiece;
            ivPiece = 0;

        }
        else
        {
            ivPiece = ivPieceNibble;
        }
        
    }



    return encryptionMode;

}
