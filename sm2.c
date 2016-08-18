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
	//set_sm2_key_init(sm2_param_digest_d_A, Group, sm2_key, pubkey);
	get_sm2_key_init(Group, sm2_key, pubkey);
	showBN(pubkey->x);
	showBN(pubkey->y);
	showBN(sm2_key->priv_key);

	/*
	**sign and verify
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
	P = BN_bn2hex(pubkey->x);
	A = BN_bn2hex(pubkey->y);
	B = BN_bn2hex(sm2_key->priv_key);
	printf("%s\n", P);
	printf("%s\n", A);
	printf("%s\n", B);
	strcat(P, A);
	strcat(P, B);
	printf("P is :\n");
	printf("sizeof P is :%d\n", sizeof(P));
	printf("strlen P is :%d\n", strlen(P));
	printf("%s\n", P);
	printf("%s\n", A);
	printf("%s\n", B);
	return 0;
}