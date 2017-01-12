#ifndef DSSE_KEYGEN_H
#define DSSE_KEYGEN_H

#include "MasterKey.h"
class DSSE_KeyGen
{
public:
    DSSE_KeyGen();
    ~DSSE_KeyGen();
    
    /*
     * Key generation functions
     */
    int genMaster_key(MasterKey *pKey, unsigned char *pPRK, int PRK_len, unsigned char *pXTS, int XTS_len, unsigned char *pSKM, int SKM_len);
    int genRow_key(unsigned char *pOutData, int out_len, unsigned char *pInData, int in_len, int serverID, MasterKey *pKey);
     
      
    /* modify functions in the libDSSE.so to be correct by this */
    int _rdrand64_asm(unsigned long int *therand);
    int invokeFortuna_prng(unsigned char *seed, unsigned char *key, int seedlen, int keylen);
    int rdrand(unsigned char* output, unsigned int output_len, unsigned int retry_limit);
};

#endif // DSSE_KEYGEN_H
