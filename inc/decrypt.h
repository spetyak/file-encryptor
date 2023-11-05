#include <stdint.h>
#ifndef DECRYPT_H_
#define DECRYPT_H_

#define BUFFER_SIZE 16                  // 16 bytes (since block length is 16 bytes)
#define BLOCK_ROW_COL_SIZE 4            // the block represented by a matrix is 4 bytes x 4 bytes

extern const uint8_t invSbox[256];

// functions for DECRYPTING data using an AES encryption scheme

// inv subbytes
uint8_t invSubByte(uint8_t inputByte);

void invSubBytes(uint8_t* block);

// inv shift row
void invShiftRows(uint8_t* block);

// inv mix columns
void invMixColumns(uint8_t* block);

#endif // DECRYPT_H_
