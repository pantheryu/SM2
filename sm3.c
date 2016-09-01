#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sm3.h"

int sm3_context_init(sm3_context *context)
{
	int i;
	for (i = 0; i < 8; i++)
		context->IV_I[i] = IV[i];

	return 0;
}

ULONG CF(sm3_context *context, ULONG BL[16])
{
	int j;
	ULONG A, B, C, D, E, F, G, H;
	ULONG SS1, SS2, TT1,TT2;
	ULONG W[68];
	ULONG W1[64];
	ULONG temp1, temp2;

	/*
	 * set W[68]
	 */

	for (j = 0; j < 16; j++)
	{
		W[j] = BL[j];
	}

	for (j = 16; j < 68; j++)
	{
		temp1 = W[j-16] ^ W[j-9] ^ CROL(W[j-3], 15);
		W[j] = P1(temp1) ^ CROL(W[j-13], 7) ^ W[j-6];
	}
	/*
	 * set W1[64]
	 */
	for (j = 0; j < 64; j++)
	{
		W1[j] = W[j] ^ W[j+4];
	}

	/*
	 * fuction CF
	 */
	A = context->IV_I[0];
	B = context->IV_I[1];
	C = context->IV_I[2];
	D = context->IV_I[3];
	E = context->IV_I[4];
	F = context->IV_I[5];
	G = context->IV_I[6];
	H = context->IV_I[7];

	for (j = 0; j < 16; j++)
	{
		temp2 = CROL(A, 12) + E + CROL(T0, j);
		SS1 = CROL(temp2, 7);
		SS2 = SS1 ^ CROL(A, 12);
		TT1 = FF0(A, B, C) + D + SS2 + W1[j];
		TT2 = GG0(E, F, G) + H + SS1 + W[j];
		D = C;
		C = CROL(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = CROL(F, 19);
		F = E;
		E = P0(TT2);
	}
	for (j = 16; j < 64; j++)
	{
		temp2 = CROL(A, 12) + E + CROL(T1, j);
		SS1 = CROL(temp2, 7);
		SS2 = SS1 ^ CROL(A, 12);
		TT1 = FF1(A, B, C) + D + SS2 + W1[j];
		TT2 = GG1(E, F, G) + H + SS1 + W[j];
		D = C;
		C = CROL(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = CROL(F, 19);
		F = E;
		E = P0(TT2);
	}
	context->IV_I[0] = A ^ context->IV_I[0];
	context->IV_I[1] = B ^ context->IV_I[1];
	context->IV_I[2] = C ^ context->IV_I[2];
	context->IV_I[3] = D ^ context->IV_I[3];
	context->IV_I[4] = E ^ context->IV_I[4];
	context->IV_I[5] = F ^ context->IV_I[5];
	context->IV_I[6] = G ^ context->IV_I[6];
	context->IV_I[7] = H ^ context->IV_I[7];

}

int sm3_hash_half(UCHAR *message, int len, sm3_context *context)
{
	int ulen;
	int i, j, k;


	i = len / 64;
	j = len % 64;
	if (j > 56)
		k = i + 2;
	else
		k = i + 1;
	ulen = (k - i) * 64;
	UCHAR uMess[ulen];
	ULONG Mess[k][16];
	UCHAR pading[128] = {
		 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0	
		};

	int m, n, temp, temp1, temp2;
	temp = 0;
	for (m = 0; m < i; m++)
	{
		for (n = 0; n < 16; n++)
		{
			Mess[m][n] = ((message[temp*4] << 24) | (message[temp*4+1] << 16) |(message[temp*4+2] << 8) | (message[temp*4+3]));
			temp ++;
		}
		CF(context, &Mess[m][0]);
	}
	temp = temp * 4;
	for (m = temp, temp1 = 0; m < len; m++, temp1++)
		uMess[temp1] = message[m];

	for (m = temp1, temp2 = 0; m < ulen; m++, temp2++)
		uMess[m] = pading[temp2];
	

	temp = 0;
	for (m = i; m < k; m++)
	{
		if (m == (k-1))
		{
			for (n = 0; n < 15; n++)
			{
				Mess[m][n] = ((uMess[temp*4] << 24) | (uMess[temp*4+1] << 16) |(uMess[temp*4+2] << 8) | (uMess[temp*4+3]));
				temp++;
			}
			Mess[m][n] = (ULONG)(len*8);
		}
		else
		{	Mess[m][n] = ((uMess[temp*4] << 24) | (uMess[temp*4+1] << 16) |(uMess[temp*4+2] << 8) | (uMess[temp*4+3]));
		}
		CF(context, &Mess[m][0]);

	}
}

int sm3_hash(UCHAR *message, int len, UCHAR *Z)
{
	sm3_context context;
	sm3_context_init(&context);
	sm3_hash_half(message, len, &context);

	int i;
	for (i = 0; i < 8; i++)
	{
		Z[4*i  ] = context.IV_I[i] >> 24;
		Z[4*i+1] = context.IV_I[i] >> 16;
		Z[4*i+2] = context.IV_I[i] >>  8;
		Z[4*i+3] = context.IV_I[i]      ;
	}

	return 0;
}

// int main(int argc, char** argv)
// {
// 	int i;
// 	sm3_context context;
// 	sm3_context_init(&context);
// 	UCHAR message[64] = "abc";
// 	printf("%d\n", int(strlen(message)));

// 	sm3_hash(message, 64, &context);
// 	for (i = 0; i < 8; i++)
// 	{	
// 		printf("%x\n", context.IV_I[i]);
// 	}
// 	return 0;
// }
