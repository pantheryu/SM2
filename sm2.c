#include "sm2.h"
#include <openssl/ec.h>

typedef struct 
{
	BIGNUM *priv_key;
	EC_POINT *pub_key;
} SM2_key;

typedef struct 
{
	BIGNUM *x;
	BIGNUM *y;
} PubKey;

typedef struct 
{
	BIGNUM *p;
	BIGNUM *a;
	BIGNUM *b;
	BIGNUM *Gx;
	BIGNUM *Gy;
	BIGNUM *n;
	EC_POINT *G;
	BN_CTX *ctx;
	EC_GROUP *group;
} group_st;

/*
**set group
 */
EC_GROUP *group_new()
{
	group_st *Group;
	Group = (group_st *)OPENSSL_malloc(sizeof(group_st));
	Group->p = BN_new();
	Group->a = BN_new();
	Group->b = BN_new();
	Group->Gx = BN_new();
	Group->Gy = BN_new();
	Group->n = BN_new();
	Group->ctx = BN_CTX_new();
	return Group;
}

int group_init(char **strValue, group_st *Group)
{
	BN_hex2bn(&Group->p, strValue[0]);
	BN_hex2bn(&Group->a, strValue[1]);
	BN_hex2bn(&Group->b, strValue[2]);
	BN_hex2bn(&Group->Gx, strValue[3]);
	BN_hex2bn(&Group->Gy, strValue[4]);
	BN_hex2bn(&Group->n, strValue[5]); 
	Group->group = EC_GROUP_new(EC_GFp_mont_method());
	EC_GROUP_set_curve_GFp(Group->group, Group->p, Group->a, Group->b, Group->ctx);

	BIGNUM *d;
	d = BN_new();
	Group->G = EC_POINT_new(Group->group);
	EC_POINT_set_compressed_coordinates_GFp(Group->group, Group->G, Group->Gx, 0, Group->ctx);
	if (!EC_POINT_is_on_curve(Group->group, Group->G, Group->ctx)) printf("error\n"); 
	EC_GROUP_set_generator(Group->group, Group->G, Group->n, BN_value_one());

	if (!EC_POINT_get_affine_coordinates_GFp(Group->group, Group->G, Group->Gx, d, Group->ctx)) printf("error\n");
	if (0 != BN_cmp(d, Group->Gy)) printf("error\n");

	if (256 != EC_GROUP_get_degree(Group->group)) printf("error\n");

	EC_POINT *Q;
	Q = EC_POINT_new(Group->group);
	EC_GROUP_get_order(Group->group, Group->n, Group->ctx);
	EC_GROUP_precompute_mult(Group->group, Group->ctx);
	EC_POINT_mul(Group->group, Q, Group->n, NULL, NULL, Group->ctx);
	if (!EC_POINT_is_at_infinity(Group->group, Q)) 
		printf("error\n");
	else
		printf("OK\n");
	return 0;
}

void group_free(group_st *Group)
{
	if (Group)
	{
		BN_free(Group->a);
		Group->a = NULL;
		BN_free(Group->b);
		Group->b = NULL;
		BN_free(Group->p);
		Group->p = NULL;
		BN_free(Group->Gx);
		Group->Gx = NULL;
		BN_free(Group->Gy);
		Group->Gy = NULL;
		BN_free(Group->n);
		Group->n = NULL;
		BN_CTX_free(Group->ctx);
		Group->ctx = NULL;
		EC_POINT_free(Group->G);
		Group->G = NULL;
		OPENSSL_free(Group);
	}
}
/*
**set key
 */
SM2_key *sm2_key_new(group_st *Group)
{
	SM2_key *key;
	key = (SM2_key *)OPENSSL_malloc(sizeof(SM2_key));
	key->priv_key = BN_new();
	key->pub_key = EC_POINT_new(Group->group);
}

void sm2_key_free(SM2_key *key)
{
	if (key)
	{
		BN_free(key->priv_key);
		key->priv_key = NULL;
		EC_POINT_free(key->pub_key);
		key->pub_key = NULL;
		OPENSSL_free(key);
	}
}

PubKey *pub_key_new()
{
	PubKey *pkey;
	pkey = (PubKey *)malloc(sizeof(PubKey));
	pkey->x = BN_new();
	pkey->y = BN_new();

	return pkey;
}

void pub_key_free(PubKey *pkey)
{
	if (pkey)
	{
		BN_free(pkey->x);
		pkey->x = NULL;
		BN_free(pkey->y);
		pkey->y = NULL;
		OPENSSL_free(pkey);
	}
}

/*
 * generate public keys according to private key that you set
 */
int set_sm2_key_init(char **str_pri, group_st *Group, SM2_key *key, PubKey *pkey)
{
	BN_hex2bn(&key->priv_key, str_pri[0]);
	if (!EC_POINT_mul(Group->group, key->pub_key, key->priv_key, NULL, NULL, Group->ctx)) return -1;
	EC_POINT_get_affine_coordinates_GFp(Group->group, key->pub_key, pkey->x, pkey->y, Group->ctx);

	EC_KEY *ec_key;
	ec_key = EC_KEY_new();
	EC_KEY_set_group(ec_key, Group->group);
 
	showBN(pkey->x);
	showBN(pkey->y);
	EC_KEY_set_private_key(ec_key, key->priv_key);
	EC_KEY_set_public_key(ec_key, key->pub_key);
	
	if (!EC_KEY_check_key(ec_key)) return -1;
	else
		printf("generate key succcess\n");

	return 0;	
}

/*
 * generate public and private keys automatically
 */
int get_sm2_key_init(group_st *Group, SM2_key *key, PubKey *pkey)
{
	EC_KEY *ecc_key;
	ecc_key = EC_KEY_new();
	EC_KEY_set_group(ecc_key, Group->group);

	EC_KEY_generate_key(ecc_key);
	EC_KEY_generate_key(ecc_key);
	if (!EC_KEY_check_key(ecc_key)) return -1;
	key->priv_key = EC_KEY_get0_private_key(ecc_key);
	key->pub_key = EC_KEY_get0_public_key(ecc_key);
	EC_POINT_get_affine_coordinates_GFp(Group->group, key->pub_key, pkey->x, pkey->y, Group->ctx);
	showBN(pkey->x);
	showBN(pkey->y);
	showBN(key->priv_key);
}

int gen_key()
{
	group_st *Group;
	Group = group_new();
	group_init(sm2_param_fp_256, Group);

	SM2_key *sm2_key;
	sm2_key = sm2_key_new(Group);
	PubKey *pubkey;
	pubkey = pub_key_new();
	//set_sm2_key_init(sm2_param_digest_d_A, Group, sm2_key, pubkey);
	get_sm2_key_init(Group, sm2_key, pubkey);
	showBN(pubkey->x);
	showBN(pubkey->y);
	showBN(sm2_key->priv_key);
}

/*generate key*/
int generate_key(char **strValue)
{
	BN_CTX *ctx = NULL;
	BIGNUM *p, *a, *b;
	EC_GROUP *group;
	BIGNUM *x, *y, *z;
	BIGNUM *test;
	EC_POINT *P;

	// CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
	// CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	// ERR_load_crypto_strings();
	//RAND_seed();
	
	ctx = BN_CTX_new();

	p = BN_new();
	a = BN_new();
	b = BN_new();
	group = EC_GROUP_new(EC_GFp_mont_method());

	BN_hex2bn(&p, strValue[0]);
	BN_hex2bn(&a, strValue[1]);
	BN_hex2bn(&b, strValue[2]);
	EC_GROUP_set_curve_GFp(group, p, a, b, ctx);

	P = EC_POINT_new(group);

	x = BN_new();
	y = BN_new();
	z = BN_new();
	BN_hex2bn(&x, strValue[3]);
	BN_hex2bn(&y, strValue[4]);
	BN_hex2bn(&z, strValue[5]);

	test = BN_new();

	EC_POINT_set_compressed_coordinates_GFp(group, P, x, 0, ctx);
	if (!EC_POINT_is_on_curve(group, P, ctx)) printf("error\n"); 
	EC_GROUP_set_generator(group, P, z, BN_value_one());

	if (!EC_POINT_get_affine_coordinates_GFp(group, P, x, test, ctx)) printf("error\n");
	if (0 != BN_cmp(y, test)) printf("error\n");

	if (256 != EC_GROUP_get_degree(group)) printf("error\n");

	showBN(p);
	showBN(a);
	showBN(b);
	showBN(x);
	showBN(y);
	showBN(z);

	EC_POINT *Q;
	Q = EC_POINT_new(group);
	EC_GROUP_get_order(group, z, ctx);
	EC_GROUP_precompute_mult(group, ctx);
	EC_POINT_mul(group, Q, z, NULL, NULL, ctx);
	if (!EC_POINT_is_at_infinity(group, Q)) 
		printf("error\n");
	else
		printf("OK\n");
	
	//showBN(key->priv_key);
	//
	
// 	char *buf[] = {
// 	//示例2：Fp-256曲线 
// 	//素数p： 
// 	"8542D69E" "4C044F18" "E8B92435" "BF6FF7DE" "45728391" "5C45517D" "722EDB8B" "08F1DFC3",
// 	//系数a： 
// 	"787968B4" "FA32C3FD" "2417842E" "73BBFEFF" "2F3C848B" "6831D7E0" "EC65228B" "3937E498",
// 	//系数b： 
// 	"63E4C6D3" "B23B0C84" "9CF84241" "484BFE48" "F61D59A5" "B16BA06E" "6E12D1DA" "27C5249A",
// 	//基点G = (x;y)，其阶记为n。 
// 	//坐标x： 
// 	"421DEBD6" "1B62EAB6" "746434EB" "C3CC315E" "32220B3B" "ADD50BDC" "4C4E6C14" "7FEDD43D",
// 	//坐标y： 
// 	"0680512B" "CBB42C07" "D47349D2" "153B70C4" "E5D7FDFC" "BFA36EA1" "A85841B9" "E46E09A2",
// 	//阶n： 
// 	"8542D69E" "4C044F18" "E8B92435" "BF6FF7DD" "29772063" "0485628D" "5AE74EE7" "C32E79B7",
// };

	// unsigned char buf[10][64];
	// int len = EC_KEY_priv2buf(key, buf);
	// printf("%s\n", buf[0]);

	char *sm2_param_digest_d_A[2] = {
	"128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263",
	"771EF3DB" "FF5F1CDC" "32B9C572" "93047619" "1998B2BF" "7CB981D7" "F5B39202" "645F0931",
};

	EC_KEY *key;
	key = EC_KEY_new();
	EC_KEY_set_group(key, group);

	BIGNUM *priv_key;
	priv_key = BN_new();
	BN_hex2bn(&priv_key, sm2_param_digest_d_A[0]);
	showBN(priv_key);
	
	EC_POINT *Epub_key;
	Epub_key = EC_POINT_new(group);
	if (!EC_POINT_mul(group, Epub_key, priv_key, NULL, NULL, ctx)) printf("error1\n");
	

	BIGNUM *p_x, *p_y;
	p_x = BN_new();
	p_y = BN_new();
	EC_POINT_get_affine_coordinates_GFp(group, Epub_key, p_x, p_y, ctx);
	showBN(p_x);
	showBN(p_y);
	EC_KEY_set_private_key(key, priv_key);
	EC_KEY_set_public_key(key, Epub_key);
	// if (!EC_KEY_set_group(key, group)) printf("error2\n");
	// if (!EC_KEY_generate_key(key)) printf("error\n");
	if (!EC_KEY_check_key(key)) printf("error3\n");
	//priv_key = EC_KEY_get0_private_key(key);
	//showBN(priv_key);

	BIGNUM *ppri_key;
	ppri_key = BN_new();
	ppri_key = EC_KEY_get0_private_key(key);
	showBN(ppri_key);

	// EC_POINT *Epub_key;
	// Epub_key = EC_POINT_new(group);
	// Epub_key = EC_KEY_get0_public_key(key);
	// EC_POINT_get_affine_coordinates_GFp(group, Epub_key, p_x, p_y, ctx);
	// showBN(p_x);
	// showBN(p_y);
	BIGNUM *pub_key;
	pub_key = BN_new();
	pub_key = EC_POINT_point2bn(group, Epub_key, POINT_CONVERSION_UNCOMPRESSED, pub_key, ctx);
	showBN(pub_key);
	// unsigned char *ppub_key;
	// ppub_key = EC_POINT_point2hex(group, Epub_key, POINT_CONVERSION_UNCOMPRESSED, ctx);
	// printf("%s\n", ppub_key);
	// unsigned char pppub[128];
	// pppub = ppub_key;
	// unsigned char pub_x[64];
	// unsigned char pub_y[64];
	// memcpy(pub_x, ppub_key, 64);
	// printf("%s\n", pub_x);

	// BIGNUM *ppub_x;
	// ppub_x = BN_new();
	// BN_hex2bn(&ppub_x, pub_x);
	// showBN(ppub_x);
}

int main(int argc, char **argv)
{
	/*
	**initialize group and generate ECC public and private keys
	 */
	group_st *Group;
	Group = group_new();
	group_init(sm2_param_fp_256, Group);

	SM2_key *sm2_key;
	sm2_key = sm2_key_new(Group);
	PubKey *pubkey;
	pubkey = pub_key_new();
	set_sm2_key_init(sm2_param_digest_d_A, Group, sm2_key, pubkey);
	//get_sm2_key_init(Group, sm2_key, pubkey);
	showBN(pubkey->x);
	showBN(pubkey->y);
	showBN(sm2_key->priv_key);

	/*
	**sign and verify
	 */
	
	/*
	 *
	 * sign
	 * 
	 */
	BIGNUM *p, *a, *b;
	p = BN_new();
	a = BN_new();
	b = BN_new();
	unsigned char *P, *A, *B;
	BN_hex2bn(&p, sm2_param_fp_256[0]);
	BN_hex2bn(&a, sm2_param_fp_256[1]);
	BN_hex2bn(&b, sm2_param_fp_256[2]);
	printf("\n\n\n\n\n");
	showBN(p);
	showBN(a);
	showBN(b);

	// char bin0[150], bin1[150], bin2[150];
	// int len0 = BN_bn2bin(p, bin0);
	// int len1 = BN_bn2bin(a, bin1);
	// int len2 = BN_bn2bin(b, bin2);
	// printf("bin: %s\n", bin0);
	// printf("bin: %s\n", bin1);
	// printf("bin: %s\n", bin2);
	// strcat(bin0, bin1);
	// strcat(bin0, bin2);
	// printf("len: %d\n", len0);
	// printf("len: %d\n", len1);
	// printf("len: %d\n", len2);
	// printf("all len: %d\n", (int)sizeof(bin0));
	// printf("all strlen: %d\n", (int)strlen(bin0));

	P = BN_bn2hex(pubkey->x);
	A = BN_bn2hex(pubkey->y);
	B = BN_bn2hex(sm2_key->priv_key);
	printf("%s\n", P);
	printf("%s\n", A);
	char whole[1000] = "";
	printf("%s\n", whole);
	//strcat(whole, info_A[1]);
	//printf("info_A_1 len: %d\n", (int)(strlen(info_A[1])));
	//printf("%s\n", whole);
	//strcat(whole, info_A[0]);
	//printf("info_A_0 len: %d\n", (int)(strlen(info_A[0])));
	//printf("%s\n", whole);
	strcat(whole, sm2_param_fp_256[1]);
	printf("sm2_param_fp_256[1]: %d\n", (int)(strlen(sm2_param_fp_256[1])));
	strcat(whole, sm2_param_fp_256[2]);
	printf("sm2_param_fp_256[2]: %d\n", (int)(strlen(sm2_param_fp_256[2])));
	strcat(whole, sm2_param_fp_256[3]);
	printf("sm2_param_fp_256[3]: %d\n", (int)(strlen(sm2_param_fp_256[3])));
	strcat(whole, sm2_param_fp_256[4]);
	printf("sm2_param_fp_256[4]: %d\n", (int)(strlen(sm2_param_fp_256[4])));
	strcat(whole, P);
	printf("strlen P: %d\n", (int)strlen(P));
	strcat(whole, A);
	printf("strlen A: %d\n", (int)strlen(A));
	printf("%s\n", whole);
	// int messlen = (int)strlen(whole);
	// printf("messlen: %d\n", messlen);

	unsigned char bin[1024];
	char *ID_A = "ALICE123@YAHOO.COM";
	int Alen, A_len, pos;
	Alen = (int)(strlen(ID_A));
	A_len = Alen * 8;
	pos = 0;
	bin[pos] = A_len / 512;
	pos ++;
	bin[pos] = A_len % 512;
	pos ++;
	memcpy(&bin[pos], ID_A, Alen);
	pos += Alen;
	BIGNUM *WH;
	WH = BN_new();
	BN_hex2bn(&WH, whole);
	int messlen = BN_num_bytes(WH);
	printf("messlen: %d\n", messlen);
	BN_bn2bin(WH, &bin[pos]);
	pos += messlen;
	printf("pos: %d\n", pos);

	sm3_context context;
	sm3_context_init(&context);
	sm3_hash(bin, pos, &context);
	int i;
	for (i = 0; i < 8; i++)
	{	
		printf("%x ", context.IV_I[i]);
	}

	unsigned char Z_A[32];
	for (i = 0; i < 8; i++)
	{
		Z_A[4*i] =   (unsigned char) ((context.IV_I[i]) >> 24);
		Z_A[4*i+1] = (unsigned char) ((context.IV_I[i]) >> 16);
		Z_A[4*i+2] = (unsigned char) ((context.IV_I[i]) >> 8 );
		Z_A[4*i+3] = (unsigned char) ((context.IV_I[i])      );
	}
	for (i = 0; i < 32; i++)
		printf("Z_A[%d]: %0x ", i, Z_A[i]);

	char *messdig = "message digest";
	int messdig_len = (int)(strlen(messdig));
	printf("messdig len: %d\n", (int)(strlen(messdig)));

	int MM_len = messdig_len + 32;
	printf("MM_len: %d\n", MM_len);
	unsigned char MM[MM_len];
	memcpy(&MM[0], Z_A, 32);
	memcpy(&MM[32], messdig, messdig_len);
	for (i = 0; i < MM_len; i++)
	{
		printf("%0x ", MM[i]);
	}
	printf("\n");

	sm3_context context1;
	sm3_context_init(&context1);
	sm3_hash(MM, MM_len, &context1);

	for (i = 0; i < 8; i++)
	{	
		printf("%x\n", context1.IV_I[i]);
	}

	unsigned char eHash[32];
	for (i = 0; i < 8; i++)
	{
		eHash[4*i  ] = (unsigned char) ((context1.IV_I[i]) >> 24);
		eHash[4*i+1] = (unsigned char) ((context1.IV_I[i]) >> 16);
		eHash[4*i+2] = (unsigned char) ((context1.IV_I[i]) >> 8 );
		eHash[4*i+3] = (unsigned char) ((context1.IV_I[i])      );
	}
	for (i = 0; i < 32; i++)
	{	
		printf(" %0x ", eHash[i]);
		if ((i+1)%4 == 0)
			printf("\n");
	}

	BIGNUM *k;
	k = BN_new();
	BN_hex2bn(&k, sm2_param_digest_k[0]);

	EC_POINT *xy1;
	xy1 = EC_POINT_new(Group->group);
	EC_POINT_mul(Group->group, xy1, k, NULL, NULL, Group->ctx);
	showBN(k);

	BIGNUM *x1, *y1;
	x1 = BN_new();
	y1 = BN_new();
	EC_POINT_get_affine_coordinates_GFp(Group->group, xy1, x1, y1, Group->ctx);
	showBN(x1);
	showBN(y1);

	BIGNUM *en, *ret1;
	BIGNUM *r, *s;
	BIGNUM *TEMP1, *TEMP2;
	en = BN_new();
	ret1 = BN_new();
	r = BN_new();
	s = BN_new();
	TEMP1 = BN_new();
	TEMP2 = BN_new();
	BN_bin2bn(eHash, 32, en);
	printf("***********en:**********\n");
	showBN(en);

	BN_mod_add(r, en, x1, Group->n, Group->ctx);
	showBN(r);
	BN_one(TEMP1);
	BN_add(TEMP1, TEMP1, sm2_key->priv_key);
	BN_mod_inverse(TEMP1, TEMP1, Group->n, Group->ctx);
	BN_mul(TEMP2, r, sm2_key->priv_key, Group->ctx);
	BN_sub(TEMP2, k, TEMP2);
	BN_mod_mul(s, TEMP1, TEMP2, Group->n, Group->ctx);
	showBN(s);
	BN_free(en);
	BN_free(ret1);
	/*
	 *
	 * verify
	 * 
	 */
	int B_MM_len = MM_len;
	int B_MM[B_MM_len];
	memcpy(B_MM, MM, B_MM_len);
	sm3_context context2;
	sm3_context_init(&context2);
	sm3_hash(B_MM, B_MM_len, &context2);
	unsigned char B_en[32];
	for (i = 0; i < 8; i++)
	{
		B_en[4*i  ] = ((context2.IV_I[i]) >> 24);
		B_en[4*i+1] = ((context2.IV_I[i]) >> 16);
		B_en[4*i+2] = ((context2.IV_I[i]) >> 8 );
		B_en[4*i+3] = ((context2.IV_I[i])      );
	}
	for (i = 0; i < 32; i++)
	{
		printf("%0x ", B_en[i]);
		if ((i+1)%4 == 0)
			printf("\n");
	}

	BIGNUM *B_e;
	B_e = BN_new();
	BN_bin2bn(B_en, 32, B_e);
	showBN(B_e);

	BIGNUM *t;
	EC_POINT *xy0, *xy00;
	BIGNUM *x0, *y0, *x00, *y00;
	t = BN_new();
	x0 = BN_new();
	y0 = BN_new();
	x00 = BN_new();
	y00 = BN_new();
	xy0 = EC_POINT_new(Group->group);
	xy00 = EC_POINT_new(Group->group);
	BN_mod_add(t, r, s, Group->n, Group->ctx);

	// EC_POINT_set_compressed_coordinates_GFp(Group->group, xy0, pubkey->x, 0, Group->ctx);
	// if (!EC_POINT_is_on_curve(Group->group, xy0, Group->ctx)) printf("error\n"); 
	// // EC_GROUP_set_generator(Group->group, Group->G, Group->n, BN_value_one());

	// if (!EC_POINT_get_affine_coordinates_GFp(Group->group, xy0, pubkey->x, k, Group->ctx)) printf("error\n");
	// if (0 != BN_cmp(pubkey->y, k)) printf("error\n");
	// showBN(k);

	EC_POINT_mul(Group->group, xy0, NULL, Group->G, s, Group->ctx);
	EC_POINT_get_affine_coordinates_GFp(Group->group, xy0, x0, y0, Group->ctx);
	EC_POINT_mul(Group->group, xy00, NULL, sm2_key->pub_key, t, Group->ctx);
	EC_POINT_get_affine_coordinates_GFp(Group->group, xy00, x00, y00, Group->ctx);
	showBN(x0);
	showBN(y0);
	showBN(x00);
	showBN(y00);

	EC_POINT *B_xy;
	BIGNUM *B_x, *B_y;
	B_xy = EC_POINT_new(Group->group);
	B_x = BN_new();
	B_y = BN_new();
	EC_POINT_add(Group->group, B_xy, xy0, xy00, Group->ctx);
	EC_POINT_get_affine_coordinates_GFp(Group->group, B_xy, B_x, B_y, Group->ctx);
	showBN(B_x);
	showBN(B_y);

	BIGNUM *B_r, *B_s;
	B_r = BN_new();
	B_s = BN_new();
	BN_mod_add(B_r, B_e, B_x, Group->n, Group->ctx);
	showBN(B_r);
	if (BN_cmp(B_r, r) != 0)
		printf("verify error\n");
	else
		printf("verify succcess\n");

	/*
	 * exchange key
	 */
	
	/*
     * set A parameters 		
	 */
	
	/*
	 * generate A public and private key
	 */

	SM2_key * sm2_key_A;
	sm2_key_A = sm2_key_new(Group);
	Public *public_A;
	public_A = pub_key_new();
	set_sm2_key_init(sm2_para_dh_d_A, Group, sm2_key_A, public_A);
	showBN(public_A->x);
	showBN(public_A->y);
	showBN(sm2_key_A->priv_key);

    BIGNUM *RA_B, *RAX_B, *RAY_B;
    EC_POINT *RA_P;

    RA_B = BN_new();
    RAX_B = BN_new();
    RAY_B = BN_new();
    RA_P = EC_POINT_new(Group->group);
    BN_hex2bn(&RA_B, sm2_param_dh_r_A[0]);
    EC_POINT_mul(Group->group, RA_P, NULL, Group->G, RA_B, Group->ctx);
    EC_POINT_get_affine_coordinates_GFp(Group->group, RA_P, RX_B, RY_B, Group->ctx);

    

    /*
     * generate B public and private keys
     */
    SM2_key *sm2_key_B;
	sm2_key_B = sm2_key_new(Group);
	PubKey *pubkey_B;
	pubkey_B = pub_key_new();
	set_sm2_key_init(sm2_param_dh_r_B, Group, sm2_key_B, pubkey_B);
	//get_sm2_key_init(Group, sm2_key, pubkey);
	showBN(pubkey_B->x);
	showBN(pubkey_B->y);
	showBN(sm2_key_B->priv_key);


    BIGNUM *RB_B, *RBX_B, *RBY_B;
    EC_POINT *RB_P;
    
    RB_B = BN_new();
    RBX_B = BN_new();
    RBY_B = BN_new();
    RB_P = EC_POINT_new(Group->group);
    BN_hex2bn(&RB_B, sm2_param_dh_r_B[0]);


	return 0;
}