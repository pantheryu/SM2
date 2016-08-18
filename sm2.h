#include <stdio.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <memory.h>
#include <openssl/evp.h>
//#include <openssl/ec/ec_lcl.h>

static void showBN(BIGNUM *bn)
{
	char *p = NULL;
	p = BN_bn2hex(bn);
	printf("%s\n", p);
	OPENSSL_free(p);
}

char *sm2_param_fp_256[] = {
	//示例2：Fp-256曲线 
	//素数p： 
	"8542D69E" "4C044F18" "E8B92435" "BF6FF7DE" "45728391" "5C45517D" "722EDB8B" "08F1DFC3",
	//系数a： 
	"787968B4" "FA32C3FD" "2417842E" "73BBFEFF" "2F3C848B" "6831D7E0" "EC65228B" "3937E498",
	//系数b： 
	"63E4C6D3" "B23B0C84" "9CF84241" "484BFE48" "F61D59A5" "B16BA06E" "6E12D1DA" "27C5249A",
	//基点G = (x;y)，其阶记为n。 
	//坐标x： 
	"421DEBD6" "1B62EAB6" "746434EB" "C3CC315E" "32220B3B" "ADD50BDC" "4C4E6C14" "7FEDD43D",
	//坐标y： 
	"0680512B" "CBB42C07" "D47349D2" "153B70C4" "E5D7FDFC" "BFA36EA1" "A85841B9" "E46E09A2",
	//阶n： 
	"8542D69E" "4C044F18" "E8B92435" "BF6FF7DD" "29772063" "0485628D" "5AE74EE7" "C32E79B7",
};

char *sm2_param_digest_d_A[2] = {
	"128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263",
	"771EF3DB" "FF5F1CDC" "32B9C572" "93047619" "1998B2BF" "7CB981D7" "F5B39202" "645F0931",
};

