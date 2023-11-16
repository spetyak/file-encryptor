#ifndef DECRYPT_H_
#define DECRYPT_H_

#include "aes.h"

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
