#include "struct_threadPrecomputedKey.h"
#include "tomcrypt_cpp.h"
#include "Miscellaneous.h"
#include "DSSE_KeyGen.h"
ThreadPrecomputedKey::ThreadPrecomputedKey()
{
    
}

ThreadPrecomputedKey::ThreadPrecomputedKey  (   TYPE_INDEX col_idx[NUM_IDX_PER_DIM],
                                    TYPE_INDEX row_idx[NUM_IDX_PER_DIM],
                                    int serverID, int op, bool genKey_decrypt,
                                    TYPE_COUNTER* row_counter,
                                    TYPE_COUNTER* col_counter,
                                    MasterKey *pKey)
{
    int seed_len = BLOCK_CIPHER_SIZE * 2; // how much is enough ? 4 + 1
	int error = 0;
   
    unsigned char *pSeed ;

    DSSE_KeyGen* dsse_keygen = new DSSE_KeyGen();
    
    TYPE_INDEX rand_len; 
    unsigned char* random_string;

    
    if(genKey_decrypt == true)
    {
        if(op ==SEARCH_OPERATION)
            rand_len = (MATRIX_COL_SIZE);
        else
            rand_len = (MATRIX_ROW_SIZE/BYTE_SIZE);
    }
    else
    {
        if(op == SEARCH_OPERATION)
            rand_len =  (MATRIX_COL_SIZE*2);
        else
            rand_len = (MATRIX_ROW_SIZE/BYTE_SIZE)*2;
    }
    random_string = new unsigned char[rand_len];
    memset(random_string,0,rand_len);
    
    pSeed = new unsigned char[seed_len];
    memset(pSeed,0,seed_len);
    
    
    this->row_counter_arr = row_counter;
    this->col_counter_arr = col_counter;

    this->pKey = pKey;
    this->op = op;
    this->genKey_decrypt = genKey_decrypt;
    
	if ((error = dsse_keygen->rdrand(pSeed,seed_len, RDRAND_RETRY_NUM)) != CRYPT_OK) 
    {
		printf("Error calling rdrand_get_n_units_retry: %d\n", error);
	}
	if ((error = dsse_keygen->invokeFortuna_prng(pSeed, random_string, seed_len, rand_len)) != CRYPT_OK) {
		printf("Error calling call_fortuna_prng function: %d\n", error);
	}
    
    for(int i = 0 ; i < NUM_IDX_PER_DIM; i++)
    {
        this->col_idx[i] = col_idx[i];
        this->row_idx[i] = row_idx[i];
    }
    this->serverID = serverID;
    //generate random keys
      
    this->precomputed_key = new unsigned char[rand_len];
    memset(this->precomputed_key,0,rand_len);
    memcpy(this->precomputed_key,random_string,rand_len);
    
    delete pSeed;
    delete dsse_keygen;
}

ThreadPrecomputedKey::~ThreadPrecomputedKey()
{
    
}

