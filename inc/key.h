#ifndef KEY_H_
#define KEY_H_

/*
 * AES operations on the key is pretty much strictly reading, 
 * so mathematical operations needn't be considered.
 * Yay for us :)
 */

// A word is "a group of 32 bits that is treated either as a single entity or as an array of 4 bytes"
#define WORDS_IN_128_BITS 4 // 128 bits contains 4 words
#define WORDS_IN_192_BITS 6 // 192 bits contains 6 words 
#define WORDS_IN_256_BITS 8 // 192 bits contains 8 words 



/*
 * An 128 bit int comprised of 4 4-byte words
 */
typedef struct uint128 {

    uint32_t words[WORDS_IN_128_BITS];

} uint128_t;

/*
 * An 192 bit int comprised of 6 4-byte words
 */
typedef struct uint192 {

    uint32_t words[WORDS_IN_192_BITS]; 

} uint192_t;

/*
 * A 256 bit int comprised of 8 4-byte words
 */
typedef struct uint256 {

    uint32_t words[WORDS_IN_256_BITS];

} uint256_t;

typedef struct myKey {

    uint32_t* keyWords;     // the array of words making up the key
    int numRounds;          // the number of rounds associated with the key's size
    int keyLengthInWords;   // the number of words making up the key
    int RconArraySize;      // the size of the Rcon array associated with the key's size

} myKey_t;

#endif // KEY_H_
