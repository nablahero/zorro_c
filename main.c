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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "zorro.h"
#include "header.h"

void printState(char * text, uint8_t * state)	{
	int i;
	printf("%s: ", text);
	for(i=0; i<16; i++)	{
		printf("%02X ", state[i]);
	}
	printf("\n");
}

void main()	{
	
	uint8_t state[16] = {
		0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x16, 0x30
	};

	uint8_t state2[16] = {
		0x71, 0x88, 0x23, 0x83, 0x00, 0x55, 0x00, 0x2a, 0x7b, 0x88, 0x23, 0x83, 0x00, 0x6D, 0x16, 0x1a
	};

	uint8_t key[16] = {
		0x74, 0xdd, 0x31, 0xf8, 0x0d, 0x81, 0x41, 0x1a, 0xec, 0x50, 0xc9, 0xe0, 0xc6, 0x81, 0x3a, 0xc2
	};
	printState("Initial State:", state);
	zorroCompleteEnc(state, key);
	printState("Ciphertext", state);
	zorroCompleteDec(state, key);
	printState("Plaintext", state);
}