#ifndef AES_H_
#define AES_H_

#include <stdint.h>

#define BUFFER_SIZE 16                  // 16 bytes (since block length is 16 bytes)
#define BLOCK_SIZE_BYTES 16             // block length is fixed at 128 bits or 16 bytes
#define AES_BLOCK_SIZE_WORDS 4          // AES block size in words
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



uint32_t subWord(uint32_t word);
uint32_t rotWord(uint32_t word);
void createKeySchedule(uint32_t* key, int keyLengthInWords, int numRounds);
void addRoundKey(uint8_t* block, int round);
void createRoundConstantArray(int RconArraySize);
void swapRowsAndColumns(uint8_t* block);
void cleanup();
void aesEncrypt(uint8_t* inBuf, int numRounds);
void aesDecrypt(uint8_t* inBuf, int numRounds);

#endif // AES_H_
