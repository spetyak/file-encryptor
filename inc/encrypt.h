#include <stdlib.h>
#ifndef ENCRYPT_H_
#define ENCRYPT_H_

#define BUFFER_SIZE 16                  // 16 bytes (since block length is 16 bytes)
#define BLOCK_ROW_COL_SIZE 4            // the block represented by a matrix is 4 bytes x 4 bytes

extern const uint8_t sbox[256];

// functions for ENCRYPTING data using an AES encryption scheme

// subbyte
uint8_t subByte(uint8_t inputByte);

// subbytes
void subBytes(uint8_t* block);

// shift row
void shiftRows(uint8_t* block);

// mix columns
void mixColumns(uint8_t* block);

#endif // ENCRYPT_H_
