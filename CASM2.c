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

	EC_POINT_free(Q);
	BN_free(d);

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

int main(int argc, char **argv)
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
	return 0;
}