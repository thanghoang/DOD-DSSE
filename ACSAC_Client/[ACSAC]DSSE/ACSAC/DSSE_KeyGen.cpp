#include "DSSE_KeyGen.h"
#include "Krawczyk128_KDF.h"        //for key generation
#include "tomcrypt_cpp.h"           // for traditional crypto primitives
#include "DSSE.h"
#include "Miscellaneous.h"
#include "string"
DSSE_KeyGen::DSSE_KeyGen()
{

}

DSSE_KeyGen::~DSSE_KeyGen()
{
}


/**
 * Generates row key for input data (row_number concatenated with pad)
 *
 * @param pOutData			Row key of the data computed is stored in it
 * @param out_len			Length of the row key
 * @param pInData			Data as input that needs to be computed
 * @param in_len			Length of input data
 * @param pKey				Key for generating row keys
 * @return 0 if successful
 * Anvesh Ragi			10-09-2013		Function created
 */
int DSSE_KeyGen::genRow_key(unsigned char *pOutData,
                     int out_len,
                     unsigned char *pInData,
                     int in_len,
                     int serverID,
                     MasterKey *pKey) {

	// cout << "Entering generate_row_key function" << endl;

	//	cout << "key : ";
	//	print_ucharstring(pKey->key3, BLOCK_CIPHER_SIZE);

	// NULL checks
	if(pKey->isNULL() || pOutData == NULL || pInData == NULL)
        return -1;
	memset(pOutData,0,out_len);
    
    if(out_len>0 && in_len>0)
    {
		// Generate the row key using OMAC AES CTR 128 function
		omac_aes128_intel(pOutData, out_len, pInData, in_len, pKey->key3[serverID]);
	//	hmac_sha256_intel(pKey->key2, pKey->skey2_3_pad_len, pInData, in_len, pOutData, out_len);
	}
    else
    {
		cout << "Either length of input or output to generate_row_key is <= 0" << endl;
    }
	// cout << "Exiting generate_row_key function" << endl << endl;
    
    
    
    
    //memcpy(pOutData,pInData,BLOCK_CIPHER_SIZE);
    //pOutData[0] = '1';
    
	return 0;
}



/**
 * Given security parameters pPRK,pXTS,pSKM; gen() outputs a master key pKey using Krawczyk KDF
 *
 * @param pKey			Master key for the whole scheme
 * @param pPRK			Security parameter/Pseudo Random Key (uniform & random intermediate key) for generating Krawczyk KDF (BLOCK_CIPHER_SIZE bytes)
 * @param PRK_len		Length of Pseudo Random Key
 * @param pXTS			Security parameter/Extractor Salt (Deterministic Seed) for generating Krawczyk PRK
 * @param XTS_len		Length of the Extractor Salt
 * @param pSKM			Security parameter/Entropy/Random Seed/Source Key Material for generating Krawczyk PRK (BLOCK_CIPHER_SIZE bytes)
 * @param SKM_len 		Length of Source Key Material
 * @return 0 if successful
 * Anvesh Ragi			10-08-2013		Function created
 */
int DSSE_KeyGen::genMaster_key(MasterKey *pKey,
        unsigned char *pPRK,
        int PRK_len,
        unsigned char *pXTS,
        int XTS_len,
        unsigned char *pSKM,
        int SKM_len){
    Krawczyk128_KDF* Kraw = new Krawczyk128_KDF();
    int ret;
	cout << "Entering dynamicsse_keygen function" << endl << endl;
    auto start = time_now;
    auto end = time_now;
    Miscellaneous misc;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end-start);
    double time;
	int error = 0;
    string key;
	//double elapsed = 0, start_time = 0, end_time = 0;
    //NULL checks
	if(pKey->isNULL() || pPRK == NULL || pXTS == NULL || pSKM == NULL )
    {
        ret = KEY_NULL_ERR;
        goto exit;
    }
	 start = time_now;
	//start_time = getCPUTime();

	// Generate Extractor salt (Deterministic Seed) using RDRAND
	if ((error = Kraw->generate_XTS(pXTS, XTS_len)) != CRYPT_OK) {
		printf("Error calling generate_XTS: %d\n", error/*error_to_string(error)*/);
		ret = KEY_GENERATION_ERR;
        goto exit;
	}

	// Generate Source Key Material using RDRAND
	if((error = Kraw->generate_128_SKM(pSKM, SKM_len)) != CRYPT_OK) {
		printf("Error calling generate_128_SKM: %d\n", error/*error_to_string(error)*/);
		ret = KEY_GENERATION_ERR;
        goto exit;
	}

	// Generate Pseudo Random Key using OMAC-128
	if((error = Kraw->generate_128_PRK(pPRK, PRK_len, pXTS, XTS_len, pSKM, SKM_len)) != CRYPT_OK) {
		printf("Error calling generate_128_PRK function: %d\n", error/*error_to_string(error)*/);
		ret = KEY_GENERATION_ERR;
        goto exit;
	}

	// Generate key1 using Krawczyk Key Derivation Function
	if((error = Kraw->generate_krawczyk_128_KDF(pKey->key1, BLOCK_CIPHER_SIZE, (unsigned char *)"key1", 4, pPRK, PRK_len)) != CRYPT_OK) {
		printf("Error calling krawczyk_128_kdf function: %d\n", error/*error_to_string(error)*/);
		ret = KEY_GENERATION_ERR;
        goto exit;
	}

	// Generate key2 using Krawczyk Key Derivation Function
	if((error = Kraw->generate_krawczyk_128_KDF(pKey->key2, BLOCK_CIPHER_SIZE, (unsigned char *)"key2", 4, pPRK, PRK_len)) != CRYPT_OK) {
		printf("Error calling krawczyk_128_kdf function: %d\n", error/*error_to_string(error)*/);
		ret = KEY_GENERATION_ERR;
        goto exit;
	}
    for(int k = 0 ; k <NUM_SERVERS ; k ++)
    {
        key = "key3" + std::to_string(k);
        // Generate key3 using Krawczyk Key Derivation Function
        if((error = Kraw->generate_krawczyk_128_KDF(pKey->key3[k], BLOCK_CIPHER_SIZE, (unsigned char*) key.c_str(), key.length(), pPRK, PRK_len)) != CRYPT_OK) {
            printf("Error calling krawczyk_128_kdf function: %d\n", error/*error_to_string(error)*/);
            ret = KEY_GENERATION_ERR;
            goto exit;
        }
    }


	//end_time = getCPUTime();
	//elapsed = /*1000.0 * */(end_time - start_time);
    end = time_now;
    elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end-start);
     time = elapsed.count() / 1000.0;
    
	//cout << "time taken for generating keys is : " << elapsed << " ms" << endl;
    cout << "time taken for generating keys is : " << time << " ms" << endl;

	cout << "Exiting dynamicsse_keygen function" << endl << endl << endl;
    ret = 0;
exit:

    delete Kraw;
	return ret;
}


/* added by Thang Hoang */


int DSSE_KeyGen::_rdrand64_asm(unsigned long int *therand)
{
	unsigned char err;
	asm volatile("rdrand %0 ; setc %1"
			: "=r" (*therand), "=qm" (err));
	return (int) err;
}
int DSSE_KeyGen::rdrand(unsigned char* output, unsigned int output_len, unsigned int retry_limit)
{
	// printf("Entering rdrand_get_n_uints_retry function \n");

	int qwords;
	int dwords;
	int i;

	unsigned long int qrand;
	unsigned int drand;
    
    int n = output_len * sizeof(unsigned long int);
    unsigned long int* tmp = new unsigned long int[n];
    
	int success;
	int count;

	int total_uints;

	unsigned long int *qptr;

	total_uints = 0;
	
	
	for (i=0; i<n; i++)
	{
		count = 0;
		do
		{
			success=_rdrand64_asm(&qrand);
		} while((success == 0) && (count++ < retry_limit));

		if (success == 1)
		{
			*tmp = qrand;
			tmp++;
			total_uints++;
		}
		else 
            return -1;
	}
    memcpy(output,tmp,output_len);
	return 0;
}
int DSSE_KeyGen::invokeFortuna_prng(unsigned char *seed, unsigned char *key, int seedlen, int keylen) {
	//printf("Entering call_fortuna_prng function \n");

	prng_state prng;
	int err, i;
	/* register prng */
	if ((err = register_prng(&fortuna_desc)) != CRYPT_OK) {
		printf("Error registering Fortuna PRNG : %s\n", error_to_string(err));
	}

	if ((err = find_prng("fortuna")) != CRYPT_OK) {
		printf("Invalid PRNG : %s\n", error_to_string(err));
	}

	/* start it */
	if ((err = fortuna_start(&prng)) != CRYPT_OK) {
		printf("Start error: %s\n", error_to_string(err));
	}

	if ((err = fortuna_add_entropy(seed, seedlen, &prng)) != CRYPT_OK) {
		printf("Add_entropy error: %s\n", error_to_string(err));
	}
	/* ready and read */
	if ((err = fortuna_ready(&prng)) != CRYPT_OK) {
		printf("Ready error: %s\n", error_to_string(err));
	}

	if ((err = fortuna_done(&prng)) != CRYPT_OK) {
		printf("Done error: %s\n", error_to_string(err));
	}

	//printf("Read %lu bytes from fortuna\n", fortuna_read(key, keylen, &prng));
    fortuna_read(key, keylen, &prng);

	//printf("Exiting call_fortuna_prng function \n");

	//printucharstring(buf,PRNG_SIZE);

	return 0;
}
