#include <stdio.h>
#include <stdlib.h>
#include <string.h>
  
#define CROL(n, j) ((((n) & 0xFFFFFFFF) << j) | (((n) & 0xFFFFFFFF) >> (32 - j)))

#define FF0(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define FF1(X, Y, Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))

#define GG0(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define GG1(X, Y, Z) (((X) & (Y)) | (~(X) & (Z)))

#define P0(X) ((X) ^ CROL(X, 9) ^ CROL(X, 17))
#define P1(X) ((X) ^ CROL(X, 15) ^ CROL(X, 23))

typedef unsigned int ULONG;
typedef unsigned char UCHAR;

typedef struct 
{
	ULONG IV_I[8];
} sm3_context;

static ULONG IV[8] = {
		0x7380166f,
		0x4914b2b9,
		0x172442d7,
		0xda8a0600,
		0xa96f30bc,
		0x163138aa,
		0xe38dee4d,
		0xb0fb0e4e,
	};
static ULONG T0 = 0x79cc4519;
static ULONG T1 = 0x7a879d8a;

int sm3_context_init(sm3_context *context);
ULONG CF(sm3_context *context, ULONG BL[16]);
int sm3_hash(UCHAR *message, int len, sm3_context *context);