#ifndef CBC_H_
#define CBC_H_

void xor(uint8_t** a, uint8_t** b);
void cbcEncrypt(uint8_t* inBuf, uint8_t* prevCipherOut, uint8_t* prevCipherIn, int numRounds, uint8_t* iv, int* firstRun);
void cbcDecrypt(uint8_t* inBuf, uint8_t* prevCipherOut, uint8_t* prevCipherIn, int numRounds, uint8_t* iv, int* firstRun);

#endif // CBC_H_