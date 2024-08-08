#ifndef PARSE_H_
#define PARSE_H_

int characterToHex(char c);
int parseInput(int* mode, myKey_t** key, uint8_t** iv, char** inputFilename, char** outputFilename);

#endif // PARSE_H_