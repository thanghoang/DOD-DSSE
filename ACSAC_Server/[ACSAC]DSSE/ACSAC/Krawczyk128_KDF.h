#ifndef KRAWCZYK128_KDF_H
#define KRAWCZYK128_KDF_H

   	
#include "tomcrypt_cpp.h"
class Krawczyk128_KDF
{
public:
    Krawczyk128_KDF();
    ~Krawczyk128_KDF();
    
    
    int generate_128_SKM(unsigned char *pSKM, int SKM_len);
    int generate_XTS(unsigned char *pXTS,int XTS_len);
    int generate_128_PRK(unsigned char *pPRK,int PRK_len,unsigned char *pXTS,int XTS_len,unsigned char *pSKM,int SKM_len);
    int generate_krawczyk_128_KDF(unsigned char *pKM,int KM_len, unsigned char *pCTXinfo, int CTXinfo_len, unsigned char *pPRK,int PRK_len);
};
#endif // KRAWCZYK128_KDF_H
