#ifndef TOKENINFO_H
#define TOKENINFO_H

#include "DSSE_Param.h"
class TokenInfo
{
private:
    TYPE_INDEX index[NUM_SERVERS];
    unsigned char serverID;
    
public:
    TokenInfo();
    ~TokenInfo();
    TYPE_INDEX getIndexBySID(unsigned char serverID);
    char getServerID();
    
    void setIndex(TYPE_INDEX idx,unsigned char serverID);
    void setServerID(unsigned char serverID);
    

};

#endif // TOKENINFO_H
