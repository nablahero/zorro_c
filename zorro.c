/**
This is a C Implementation of the Zorro Cipher designed by Gerard et al.

The MIT License (MIT)

Copyright (c) 2015 Christian Walter

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */
#define DEBUG 1
#include <stdint.h>
#include <stdio.h>

uint8_t s[256] = {
	0xB2, 0xE5, 0x5E, 0xFD, 0x5F, 0xC5, 0x50, 0xBC, 0xDC, 0x4A, 0xFA, 0x88, 0x28, 0xD8, 0xE0, 0xD1,
	0xB5, 0xD0, 0x3C, 0xB0, 0x99, 0xC1, 0xE8, 0xE2, 0x13, 0x59, 0xA7, 0xFB, 0x71, 0x34, 0x31, 0xF1,
	0x9F, 0x3A, 0xCE, 0x6E, 0xA8, 0xA4, 0xB4, 0x7E, 0x1F, 0xB7, 0x51, 0x1D, 0x38, 0x9D, 0x46, 0x69,
	0x53, 0x0E, 0x42, 0x1B, 0x0F, 0x11, 0x68, 0xCA, 0xAA, 0x06, 0xF0, 0xBD, 0x26, 0x6F, 0x00, 0xD9,
	0x62, 0xF3, 0x15, 0x60, 0xF2, 0x3D, 0x7F, 0x35, 0x63, 0x2D, 0x67, 0x93, 0x1C, 0x91, 0xF9, 0x9C,
	0x66, 0x2A, 0x81, 0x20, 0x95, 0xF8, 0xE3, 0x4D, 0x5A, 0x6D, 0x24, 0x7B, 0xB9, 0xEF, 0xDF, 0xDA,
	0x58, 0xA9, 0x92, 0x76, 0x2E, 0xB3, 0x39, 0x0C, 0x29, 0xCD, 0x43, 0xFE, 0xAB, 0xF5, 0x94, 0x23,
	0x16, 0x80, 0xC0, 0x12, 0x4C, 0xE9, 0x48, 0x19, 0x08, 0xAE, 0x41, 0x70, 0x84, 0x14, 0xA2, 0xD5,
	0xB8, 0x33, 0x65, 0xBA, 0xED, 0x17, 0xCF, 0x96, 0x1E, 0x3B, 0x0B, 0xC2, 0xC8, 0xB6, 0xBB, 0x8B,
	0xA1, 0x54, 0x75, 0xC4, 0x10, 0x5D, 0xD6, 0x25, 0x97, 0xE6, 0xFC, 0x49, 0xF7, 0x52, 0x18, 0x86,
	0x8D, 0xCB, 0xE1, 0xBF, 0xD7, 0x8E, 0x37, 0xBE, 0x82, 0xCC, 0x64, 0x90, 0x7C, 0x32, 0x8F, 0x4B,
	0xAC, 0x1A, 0xEA, 0xD3, 0xF4, 0x6B, 0x2C, 0xFF, 0x55, 0x0A, 0x45, 0x09, 0x89, 0x01, 0x30, 0x2B,
	0xD2, 0x77, 0x87, 0x72, 0xEB, 0x36, 0xDE, 0x9E, 0x8C, 0xDB, 0x6C, 0x9B, 0x05, 0x02, 0x4E, 0xAF,
	0x04, 0xAD, 0x74, 0xC3, 0xEE, 0xA6, 0xF6, 0xC7, 0x7D, 0x40, 0xD4, 0x0D, 0x3E, 0x5B, 0xEC, 0x78,
	0xA0, 0xB1, 0x44, 0x73, 0x47, 0x5C, 0x98, 0x21, 0x22, 0x61, 0x3F, 0xC6, 0x7A, 0x56, 0xDD, 0xE7,
	0x85, 0xC9, 0x8A, 0x57, 0x27, 0x07, 0x9A, 0x03, 0xA3, 0x83, 0xE4, 0x6A, 0xA5, 0x2F, 0x79, 0x4F
};

uint8_t inv_s[256] = {
	0x3E, 0xBD, 0xCD, 0xF7, 0xD0, 0xCC, 0x39, 0xF5, 0x78, 0xBB, 0xB9, 0x8A, 0x67, 0xDB, 0x31, 0x34, 
	0x94, 0x35, 0x73, 0x18, 0x7D, 0x42, 0x70, 0x85, 0x9E, 0x77, 0xB1, 0x33, 0x4C, 0x2B, 0x88, 0x28, 
	0x53, 0xE7, 0xE8, 0x6F, 0x5A, 0x97, 0x3C, 0xF4, 0x0C, 0x68, 0x51, 0xBF, 0xB6, 0x49, 0x64, 0xFD, 
	0xBE, 0x1E, 0xAD, 0x81, 0x1D, 0x47, 0xC5, 0xA6, 0x2C, 0x66, 0x21, 0x89, 0x12, 0x45, 0xDC, 0xEA, 
	0xD9, 0x7A, 0x32, 0x6A, 0xE2, 0xBA, 0x2E, 0xE4, 0x76, 0x9B, 0x09, 0xAF, 0x74, 0x57, 0xCE, 0xFF, 
	0x06, 0x2A, 0x9D, 0x30, 0x91, 0xB8, 0xED, 0xF3, 0x60, 0x19, 0x58, 0xDD, 0xE5, 0x95, 0x02, 0x04, 
	0x43, 0xE9, 0x40, 0x48, 0xAA, 0x82, 0x50, 0x4A, 0x36, 0x2F, 0xFB, 0xB5, 0xCA, 0x59, 0x23, 0x3D, 
	0x7B, 0x1C, 0xC3, 0xE3, 0xD2, 0x92, 0x63, 0xC1, 0xDF, 0xFE, 0xEC, 0x5B, 0xAC, 0xD8, 0x27, 0x46, 
	0x71, 0x52, 0xA8, 0xF9, 0x7C, 0xF0, 0x9F, 0xC2, 0x0B, 0xBC, 0xF2, 0x8F, 0xC8, 0xA0, 0xA5, 0xAE, 
	0xAB, 0x4D, 0x62, 0x4B, 0x6E, 0x54, 0x87, 0x98, 0xE6, 0x14, 0xF6, 0xCB, 0x4F, 0x2D, 0xC7, 0x20, 
	0xE0, 0x90, 0x7E, 0xF8, 0x25, 0xFC, 0xD5, 0x1A, 0x24, 0x61, 0x38, 0x6C, 0xB0, 0xD1, 0x79, 0xCF, 
	0x13, 0xE1, 0x00, 0x65, 0x26, 0x10, 0x8D, 0x29, 0x80, 0x5C, 0x83, 0x8E, 0x07, 0x3B, 0xA7, 0xA3, 
	0x72, 0x15, 0x8B, 0xD3, 0x93, 0x05, 0xEB, 0xD7, 0x8C, 0xF1, 0x37, 0xA1, 0xA9, 0x69, 0x22, 0x86, 
	0x11, 0x0F, 0xC0, 0xB3, 0xDA, 0x7F, 0x96, 0xA4, 0x0D, 0x3F, 0x5F, 0xC9, 0x08, 0xEE, 0xC6, 0x5E, 
	0x0E, 0xA2, 0x17, 0x56, 0xFA, 0x01, 0x99, 0xEF, 0x16, 0x75, 0xB2, 0xC4, 0xDE, 0x84, 0xD4, 0x5D, 
	0x3A, 0x1F, 0x44, 0x41, 0xB4, 0x6D, 0xD6, 0x9C, 0x55, 0x4E, 0x0A, 0x1B, 0x9A, 0x03, 0x6B, 0xB7
};

void printSBOXHex2Dec()	{
	int i;
	for (i = 0; i < 256; i++)	{
		printf("%d ,", s[i]);
	}
	printf("\n");
}

/**
 * Function to print the internal state of Zorro
 * @param state Internal State
 */
void printInternalState(uint8_t * state)	{
	int i,j;
	for(i = 0; i < 4; i++)	{
		for(j = 0; j < 4; j++)	{
			printf("%02X ", state[(j*4)+i]);
		}
		printf("\n");
	}
	printf("\n");
}

/**
 * Function to do the Galois Field Multiplication by b in 2_8
 * @param  a 
 * @param  b 
 * @return   b * a
 */
uint8_t mulGaloisField2_8(uint8_t a, uint8_t b) {
uint8_t p = 0;
uint8_t hi_bit_set;
uint8_t counter;
	for (counter = 0; counter < 8; counter++) {
		if ((b & 1) == 1)
		p ^= a;
		hi_bit_set = (a & 0x80);
		a <<= 1;
		if (hi_bit_set == 0x80)
			a ^= 0x1b;
		b >>= 1;
	}
	return p;
}

/**
 * MixColumn Operation on one Column - Similar to AES
 * @param column One Column of the State
 */
void mixColumn(uint8_t* column) {
uint8_t i;
uint8_t cpy[4];
	for(i = 0; i < 4; i++) {
		cpy[i] = column[i];
	}
	column[0] = mulGaloisField2_8(cpy[0], 2) ^
	mulGaloisField2_8(cpy[1], 3) ^
	mulGaloisField2_8(cpy[2], 1) ^
	mulGaloisField2_8(cpy[3], 1);
	column[1] = mulGaloisField2_8(cpy[0], 1) ^
	mulGaloisField2_8(cpy[1], 2) ^
	mulGaloisField2_8(cpy[2], 3) ^
	mulGaloisField2_8(cpy[3], 1);
	column[2] = mulGaloisField2_8(cpy[0], 1) ^
	mulGaloisField2_8(cpy[1], 1) ^
	mulGaloisField2_8(cpy[2], 2) ^
	mulGaloisField2_8(cpy[3], 3);
	column[3] = mulGaloisField2_8(cpy[0], 3) ^
	mulGaloisField2_8(cpy[1], 1) ^
	mulGaloisField2_8(cpy[2], 1) ^
	mulGaloisField2_8(cpy[3], 2);
}

/**
 * MixColumn Operation on all Column - Similar to AES
 * @param internBuffer internal state
 */
void zorro_MixColumns(uint8_t* internBuffer) {
int i, j;
uint8_t column[4];
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			column[j] = internBuffer[(i * 4) + j];
		}
		mixColumn(column);
		for (j = 0; j < 4; j++) {
			internBuffer[(i * 4) + j] = column[j];
		}
	}
}

/**
 * One Complete ROUND of Zorro (Not step)
 * @param state state
 * @param round round counter
 */
void zorroOneRoundEnc(uint8_t * state, uint8_t round)	{
/* SubBytes - AddConstant - ShiftRows - MixColumns */
#ifdef DEBUG
	printf("Round %i\n", round);
#endif
	/* SubBytes */
	state[0] 	= s[state[0]];
	state[4] 	= s[state[4]];
	state[8] 	= s[state[8]];
	state[12] 	= s[state[12]];
#ifdef DEBUG
	printf("SubBytes State:\n");
	printInternalState(state);
#endif
	/* Add Constant */
	state[0]	= state[0] ^ round;
	state[4]	= state[4] ^ round;
	state[8]	= state[8] ^ round;
	state[12]	= state[12] ^ (round << 3);
#ifdef DEBUG
	printf("Add Constant State:\n");
	printInternalState(state);
#endif
	/* Shift Rows */
	uint8_t tmp = state[1];
	state[1]	= state[5];
	state[5]	= state[9];
	state[9]	= state[13];
	state[13]	= tmp;

	tmp			= state[2];
	state[2]	= state[10];
	state[10]	= tmp;
	tmp			= state[6];
	state[6]	= state[14];
	state[14]	= tmp;

	tmp			= state[3];
	state[3]	= state[15];
	state[15]	= state[11];
	state[11]	= state[7];
	state[7]	= tmp;
#ifdef DEBUG
	printf("Shift Rows State:\n");
	printInternalState(state);
#endif
	/* MixColumn */
	zorro_MixColumns(state);
#ifdef DEBUG
	printf("MixColumns State:\n");
	printInternalState(state);
#endif

};

/**
 * One Complete ROUND of Zorro (Not step)
 * @param state state
 * @param round round counter
 */
void zorroOneRoundDec(uint8_t * state, uint8_t round)	{
/* Inverse MixColumn, InvShiftRows, AddConstant, InvSubBytes */
#ifdef DEBUG
	printf("Round %i\n", round);
#endif
	/* SubBytes */
	state[0] 	= s[state[0]];
	state[4] 	= s[state[4]];
	state[8] 	= s[state[8]];
	state[12] 	= s[state[12]];
#ifdef DEBUG
	printf("SubBytes State:\n");
	printInternalState(state);
#endif
	/* Add Constant */
	state[0]	= state[0] ^ round;
	state[4]	= state[4] ^ round;
	state[8]	= state[8] ^ round;
	state[12]	= state[12] ^ (round << 3);
#ifdef DEBUG
	printf("Add Constant State:\n");
	printInternalState(state);
#endif
	/* Shift Rows */
	uint8_t tmp = state[1];
	state[1]	= state[5];
	state[5]	= state[9];
	state[9]	= state[13];
	state[13]	= tmp;

	tmp			= state[2];
	state[2]	= state[10];
	state[10]	= tmp;
	tmp			= state[6];
	state[6]	= state[14];
	state[14]	= tmp;

	tmp			= state[3];
	state[3]	= state[15];
	state[15]	= state[11];
	state[11]	= state[7];
	state[7]	= tmp;
#ifdef DEBUG
	printf("Shift Rows State:\n");
	printInternalState(state);
#endif
	/* MixColumn */
	zorro_MixColumns(state);
#ifdef DEBUG
	printf("MixColumns State:\n");
	printInternalState(state);
#endif

};

/**
 * One complete Step (consiting of four rounds) of Zorro
 * @param state 
 * @param key   
 * @param round 
 */
void zorroFourRoundEnc(uint8_t * state, uint8_t * key, uint8_t round)	{
/* 4 Rounds - KeyAddition */
	int i;
	for(i = 0; i < 4; i++)	{
		zorroOneRoundEnc(state, round);
		round++;
	}
#ifdef DEBUG
	printf("Key Addition with Key: ");
#endif
	/* Key addition */
	for(i = 0; i < 16; i++)	{
		state[i] ^= key[i];
#ifdef DEBUG
		printf("%02X ", key[i]);
#endif
	}
#ifdef DEBUG
	printf("\n");
	printf("KeyAddition State #R%d:\n", round);
	printInternalState(state);
#endif
};

/**
 * Function to calculate one step of Zorro in the decryption process
 * @param state [description]
 * @param key   [description]
 * @param round [description]
 */
void zorroFourRoundDec(uint8_t * state, uint8_t * key, uint8_t round)	{
/* 4 Rounds - KeyAddition */
	int i;
	for(i = 0; i < 4; i++)	{
		zorroOneRoundDec(state, round);
		round--;
	}

	printf("Key Addition with Key: ");
	/* Key addition */
	for(i = 0; i < 16; i++)	{
		state[i] ^= key[i];
		printf("%02X ", key[i]);
	}
	printf("\n");
#ifdef DEBUG
	printf("KeyAddition State #R%d:\n", round);
	printInternalState(state);
#endif
};

/**
 * Complete Zorro Algorithm. This one should be called from the outside.
 * @param state Pointer to the state
 * @param key   Pointer to the key
 */
void zorroCompleteEnc(uint8_t * state, uint8_t * key)	{
/* Key Whitening - 6 x 4 Rounds of Zorro */
	int i = 0;
	int round = 1;

	/* Key Whitening */
	for(i = 0; i < 16; i++)	{
		state[i] ^= key[i];
	}
#ifdef DEBUG
	printf("After InitialKeyXOR State:\n");
	printInternalState(state);
#endif

	/* 6 x 4 Rounds of Zorro */
	for(i = 0; i < 6; i++)	{
		zorroFourRoundEnc(state, key, round);
		round += 4;
	}
}

void zorroCompleteDec(uint8_t * state, uint8_t * key)	{
/* Key Whitening - 6 x 4 Rounds of Zorro */
	int i, round = 23;

	/* Key Whitening */
	for(i = 0; i < 16; i++)	{
		state[i] ^= key[i];
	}
#ifdef DEBUG
	printf("After InitialKeyXOR State:\n");
	printInternalState(state);
#endif

	/* 6 x 4 Rounds of Zorro */
	for(i = 0; i < 6; i++)	{
		zorroFourRoundDec(state, key, round);
		round -= 4;
	}
	printSBOXHex2Dec();
}