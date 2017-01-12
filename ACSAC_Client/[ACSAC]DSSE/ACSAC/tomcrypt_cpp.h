
extern "C" {
#include <tomcrypt.h>	
									                                                           // For cryptographic functions, external C header file
}


// External linkage C cryptographic functions to be used
extern "C"
{

// External C functions for file operations
//int readfilesize(char *pFileName, const char *pPath);
//int readfile(char *pFileName, const char *pPath, unsigned char *pInData);
//int writefile(char *pFileName, const char *pPath, unsigned char *pOutData);

// External C functions for utilizing AES128 cryptographic functionalities of Intel AES-NI library (which uses Intel assembly instructions)
int aes128_cbc_encrypt(const unsigned char *pPlainText, unsigned char *pCipherText, const unsigned char *pKeyCipher, const unsigned char *IV,  size_t num_blocks);
int aes128_cbc_decrypt(const unsigned char *pCipherText, unsigned char *pPlainText, const unsigned char *pKeyCipher, const unsigned char *IV, size_t num_blocks);
int aes128_ctr_encdec(const unsigned char *pPlainText, unsigned char *pCipherText, const unsigned char *pKeyCipher, const unsigned char *pInitialCounter,  size_t num_blocks);

// External C function for generating random numbers (utilizing RDRAND library(implemented using assembly instructions) which uses hardware environment variables to generate random numbers)
int rdrand_get_n_uints_retry(unsigned int n, unsigned int retry_limit, unsigned int *pSeed);

// External C function for utilizing Pseudo-random number generator functionalities of tomcrypt library
int call_fortuna_prng(unsigned int *pSeed, unsigned char *pKeyCipherOrHash, int seed_len, int key_len);

// External C functions for utilizing  SHA-256 cryptographic functionalities of tomcrypt library
int sha256_intel_init(hash_state *sha_256);
int sha256_intel_process(hash_state *sha_256, const unsigned char *data, unsigned long len);
int sha256_intel_done(hash_state *sha_256, unsigned char *hash);
int sha256_intel_memory(int hash, const unsigned char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen);
int sha256_intel(unsigned char *in, int inlen, unsigned char *out);

// External C functions for utilizing HMAC cryptographic functionalities of tomcrypt library
int hmac_sha256_intel_init(hmac_state *hmac, int hash, const unsigned char *key, unsigned long keylen);
int hmac_sha256_intel_process(hmac_state *hmac, const unsigned char *in, unsigned long inlen);
int hmac_sha256_intel_done(hmac_state *hmac, unsigned char *out, unsigned long *outlen);
int hash_sha256_intel_memory(int hash, const unsigned char *key,  unsigned long keylen, const unsigned char *in, unsigned long inlen,
		unsigned char *out,  unsigned long *outlen);
int hmac_sha256_intel(unsigned char *key, int keylen, unsigned char *data, int datalen, unsigned char *out, int outlen);				//hmac_sha256_intel takes outlen (is same as outlen of its hash function sha256_intel) as input & should be <=32. Note: key_size <=64 is advised

// External C functions for utilizing OMAC cryptographic functionalities of tomcrypt library
int omac_aesni_init(omac_state *omac, int cipher, unsigned char *key);
int omac_aesni_process(omac_state *omac, unsigned char *key, const unsigned char *in, unsigned long inlen);
int omac_aesni_done(omac_state *omac, unsigned char *key, unsigned char *out, int outlen);
int omac_aes128_intel(unsigned char *out, int outlen, const unsigned char *data, int datalen, unsigned char *key);							//Key is of 16 bytes & so outlen should be <=16

// External C functions for encrypting/decrypting and authenticating a message using CCM cryptographic functionality of tomcrypt library
int ccm_128_encrypt(unsigned char *key, unsigned long keylen, unsigned char *nonce, unsigned long noncelen, unsigned char *header, unsigned long headerlen,
		unsigned char *pt, unsigned long ptlen, unsigned char *ct, unsigned char *tag, unsigned long *taglen);
int ccm_128_decrypt(unsigned char *key, unsigned long keylen, unsigned char *nonce, unsigned long noncelen, unsigned char *header, unsigned long headerlen,
		unsigned char *ct, unsigned long ctlen, unsigned char *pt, unsigned char *tag, unsigned long *taglen, unsigned char *tagcp);
int ccm_128_enc_dec(int cipher, const unsigned char *key, unsigned long keylen, symmetric_key *uskey, const unsigned char *nonce,
		unsigned long noncelen, const unsigned char *header, unsigned long headerlen, unsigned char *pt, unsigned long ptlen,
		unsigned char *ct, unsigned char *tag, unsigned long *taglen, int  direction);



}
