#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

int main(int argc, char *argv[])
{
	const EVP_CIPHER *cipher;
	const EVP_MD *dgst = NULL;
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	const char *password = "a";
	const unsigned char *salt = "\x12\xDC\xCC\x44\x5C\x8F\xDD\x35";
	int i;

	OpenSSL_add_all_algorithms();

	cipher = EVP_get_cipherbyname("des-ecb");
	if(!cipher) { fprintf(stderr, "no such cipher\n"); return 1; }

	dgst=EVP_get_digestbyname("md5");
	if(!dgst) { fprintf(stderr, "no such digest\n"); return 1; }

	if(!EVP_BytesToKey(cipher, dgst, salt,
				(unsigned char *) password,
				strlen(password), 1, key, iv))
	{
		fprintf(stderr, "EVP_BytesToKey failed\n");
		return 1;
	}

	printf("Key: "); for(i=0; i<cipher->key_len; ++i) { printf("%02x", key[i]); } printf("\n");
	printf("IV: "); for(i=0; i<cipher->iv_len; ++i) { printf("%02x", iv[i]); } printf("\n");

	return 0;
}
