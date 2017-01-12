#include "CTokenInfo.h"

TokenInfo::TokenInfo()
{
    for (int i = 0 ; i < NUM_SERVERS;i++)
    {
        this->index[i] = ZERO_VALUE;
    }
    this->serverID = ZERO_VALUE;

}

TokenInfo::~TokenInfo()
{
}

TYPE_INDEX TokenInfo::getIndexBySID(unsigned char serverID)
{
    return this->index[(int)serverID];
}
char TokenInfo::getServerID()
{
    return this->serverID;
}
    
void TokenInfo::setIndex(TYPE_INDEX idx, unsigned char serverID)
{
    this->index[(int)serverID] = idx;
}
void TokenInfo::setServerID( unsigned char serverID)
{
    this->serverID = serverID;
}
    

