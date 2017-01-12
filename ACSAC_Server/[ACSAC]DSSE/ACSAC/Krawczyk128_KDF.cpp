#include "DSSE_Param.h"
#include "Krawczyk128_KDF.h"

#include <iostream>

using namespace std;

Krawczyk128_KDF::Krawczyk128_KDF()
{
    
}
Krawczyk128_KDF::~Krawczyk128_KDF()
{

}
/*
 * DynamicSSE_Krawczyk128_KDF.cpp
 *
 *  Created on: Oct 10, 2013
 *      Author: anvesh
 */

/**
 * Generates Source Key Material(SKM) for Krawczyk PRK. RDRAND takes unsigned int array type as input, so should type cast it to unsigned char array
 *
 * @param pSKM			Security parameter/Entropy/Random Seed/Source Key Material generated using RDRAND (BLOCK_CIPHER_SIZE bytes)
 * @param SKM_len       Length of Source Key Material
 * @return 0 if successful
 * Anvesh Ragi			10-08-2013		Function created
 */
int Krawczyk128_KDF::generate_128_SKM(unsigned char *pSKM, int SKM_len) {

	// cout << "Entering generate_128_SKM function" << endl;

	int error = 0;
	// NULL checks
	if(pSKM==NULL)
    {
        return -1;
    }

	if(SKM_len>0)
    {
		// Since RDRAND tkaes unsinged int * as input, allocate memory appropriately equivalent to it's unsigned char * memory
		int SKM_length = SKM_len/4 + 1;
		unsigned int *pSourceKeyMaterial;

		pSourceKeyMaterial = new unsigned int[SKM_length];

		cout << "Generating Source Key Material..." << endl;
		/*	Initialize key using RDRAND == generating Source Key Material in int	*/
		if ((error = rdrand_get_n_uints_retry(SKM_length, RDRAND_RETRY_NUM, pSourceKeyMaterial)) != CRYPT_OK) 
        {
			printf("Error calling rdrand_get_n_units_retry: %d\n", error/*error_to_string(error)*/);
			return -1;
		}

		memcpy(pSKM,pSourceKeyMaterial,BLOCK_CIPHER_SIZE);

		delete[] pSourceKeyMaterial;
		pSourceKeyMaterial = NULL;
	}else{
		cout << "Length of Source Key Material is <= 0" << endl;
	}

	// cout << "Exiting generate_128_SKM function" << endl << endl;

	return 0;
}

/**
 * Generates Extractor Salt(XTS) for Krawczyk PRK
 *
 * @param pXTS			Security parameter/Extractor Salt (Deterministic Seed) generated using RDRAND
 * @param XTS_len		Length of the Extractor Salt
 * @return 0 if successful
 * Anvesh Ragi			10-08-2013		Function created
 */
int Krawczyk128_KDF::generate_XTS(unsigned char *pXTS,
                 int XTS_len) {

	// cout << "Entering generate_XTS function" << endl;

	int error = 0;

	// NULL check
	if(pXTS==NULL)
    {
        return -1;
    }

	if(XTS_len>0){
		// Since RDRAND tkaes unsinged int * as input, allocate memory appropriately equivalent to it's unsigned char * memory
		int XTS_length = (XTS_len/4) + 1;
		unsigned int *pExtractorSalt;

		pExtractorSalt = new unsigned int[XTS_length];

		cout << "Generating Extractor Salt..." << endl;
		// Generating Extractor Salt using RDRAND
		if ((error = rdrand_get_n_uints_retry(XTS_length, RDRAND_RETRY_NUM, pExtractorSalt)) != CRYPT_OK) {
			printf("Error calling rdrand_get_n_units_retry: %d\n", error/*error_to_string(error)*/);
			return -1;
		}

		memcpy(pXTS,pExtractorSalt,XTS_len);

		delete[] pExtractorSalt;
		pExtractorSalt = NULL;
	}
	else{
		cout << "Length of Extractor Salt is <= 0" << endl;
	}

	// cout << "Exiting generate_XTS function" << endl << endl;

	return 0;
}

/**
 * Generates Pseudo Random Key (PRK) for Krawczyk KDF (BLOCK_CIPHER_SIZE bytes)
 *
 * @param pPRK			Security parameter/Pseudo Random Key (uniform & random intermediate key) generated using omac_aes128_intel
 * @param PRK_len		Length of Pseudo Random Key
 * @param pXTS			Security parameter/Extractor Salt (Deterministic Seed) generated using RDRAND
 * @param XTS_len		Length of the Extractor Salt
 * @param pSKM			Security parameter/Entropy/Random Seed/Source Key Material generated using RDRAND (BLOCK_CIPHER_SIZE bytes)
 * @param SKM_len       Length of Source Key Material
 * @return 0 if successful
 * Anvesh Ragi			10-08-2013		Function created
 */
int Krawczyk128_KDF::generate_128_PRK(unsigned char *pPRK,
                     int PRK_len,
                     unsigned char *pXTS,
                     int XTS_len,
                     unsigned char *pSKM,
                     int SKM_len) {

	// cout << "Entering generate_128_PRK function" << endl;

	int error = 0;

	//NULL checks
	if ( pPRK == NULL || pXTS == NULL || pSKM == NULL)
    {
        return -1;
    }
	
	if(XTS_len>0 && PRK_len>0 && pSKM>0){
		cout << "Generating Pseudo Random Key..." << endl;
		if ((error = omac_aes128_intel(pPRK, BLOCK_CIPHER_SIZE, pXTS, XTS_len, pSKM)) != CRYPT_OK) {
			printf("Error calling omac_aes128_intel: %d\n", error/*error_to_string(error)*/);
			return -1;
		}
	}else{
		cout << "Either length of Pseudo Random Key or Extractor salt or Source Key Material is <= 0" << endl;
	}

	// cout << "Exiting generate_128_PRK function" << endl << endl;

	return 0;
}

/**
 * Generates Key Material (KM) from Krawczyk PRK (BLOCK_CIPHER_SIZE bytes)
 *
 * @param pKM			Key Material generated using omac_aes128_intel
 * @param KM_len		Length of Key Material
 * @param pCTXinfo		Label of Key Material
 * @param CTXinfo_len	Length of label pCTXinfo
 * @param pPRK			Security parameter/Pseudo Random Key (uniform & random intermediate key) for generating Krawczyk KDF (BLOCK_CIPHER_SIZE bytes)
 * @return 0 if successful
 * Anvesh Ragi			10-08-2013		Function created
 */
//int generate_128_KM(unsigned char *pKM,
//					  unsigned char *pCTXinfo,
//					  int CTXinfo_len,
//					  unsigned char *pPRK) {
//
//	cout << "Entering generate_128_KM function" << endl;
//
//	if ((gsError = omac_aes128_intel(pKM, BLOCK_CIPHER_SIZE, pCTXinfo, CTXinfo_len, pPRK)) != CRYPT_OK) {
//		printf("Error calling omac_aes128_intel: %d\n", gsError/*error_to_string(error)*/);
//		return -1;
//	}
//
//	cout << "Exiting generate_128_KM function" << endl << endl;
//
//	return 0;
//}

/**
 * Krawczyk Key Derivation Function (KDF) produces uniform & random keys. Generates Key Material (KM) from Krawczyk PRK of size KM_len (<=BLOCK_CIPHER_SIZE bytes)
 *
 * @param pKM			Key Material generated using omac_aes128_intel
 * @param KM_len		Length of Key Material
 * @param pCTXinfo		Label of Key Material
 * @param CTXinfo_len	Length of label pCTXinfo
 * @param pPRK			Security parameter/Pseudo Random Key (uniform & random intermediate key) for generating Krawczyk KDF (BLOCK_CIPHER_SIZE bytes)
 * @param PRK_len		Length of Psedo Random Key
 * @return 0 if successful
 * Anvesh Ragi			10-08-2013		Function created
 */
int Krawczyk128_KDF::generate_krawczyk_128_KDF(unsigned char *pKM,
                     int KM_len,
                     unsigned char *pCTXinfo,
                     int CTXinfo_len,
                     unsigned char *pPRK,
                     int PRK_len){

	// cout << "Entering krawczyk_128_KDF function" << endl;

	int error = 0;
	unsigned char *pKeyMaterial;

	// NULL checks
	if(pKM == NULL || pCTXinfo == NULL || pPRK==NULL)
    {
        return -1;
    }
	
	pKeyMaterial = new unsigned char[BLOCK_CIPHER_SIZE];

	if(KM_len>0 && CTXinfo_len &&  PRK_len){
		cout << "Generating Random & Uniform Key \"" << pCTXinfo << "\" using Krawczyk Key Derivation Function..." << endl;
		if ((error = omac_aes128_intel(pKeyMaterial, BLOCK_CIPHER_SIZE, pCTXinfo, CTXinfo_len, pPRK)) != CRYPT_OK) {
			printf("Error calling omac_aes128_intel: %d\n", error/*error_to_string(error)*/);
			return -1;
		}

		memcpy(pKM,pKeyMaterial,KM_len);

		delete[] pKeyMaterial;
		pKeyMaterial = NULL;
	}else{
		cout << "Either length of Key Material or Label of Key Material or Pseudo Random Key is <= 0" << endl;
	}

	// cout << "Exiting krawczyk_128_KDF function" << endl << endl;

	return 0;
}



