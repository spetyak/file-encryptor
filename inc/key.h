#ifndef KEY_H_
#define KEY_H_

/*
 * AES operations on the key is pretty much strictly reading, 
 * so mathematical operations needn't be considered.
 * Yay for us :)
 */



/*
 * An 128 bit int comprised of 4 4-byte words
 *
 */
typedef struct uint128 {

    uint32_t w[4]; // 128 bits contains 4 words (4 x 4 bytes)

} uint128_t;

/*
 * An 192 bit int comprised of 6 4-byte words
 *
 */
typedef struct uint192 {

    uint32_t w[6]; // 192 bits contains 6 words (6 x 4 bytes)

} uint192_t;

/*
 * A 256 bit int comprised of 8 4-byte words
 *
 */
typedef struct uint256 {

    uint32_t w[8]; // 256 bits contains 8 words (8 x 4 bytes)

} uint256_t;

typedef struct key {

    uint32_t* keyWords;
    int numRounds;
    int keyCanonLength;
    int RconArraySize;

} key_t;

#endif // KEY_H_
