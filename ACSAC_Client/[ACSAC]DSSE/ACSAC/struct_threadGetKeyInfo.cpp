#include "struct_threadGetKeyInfo.h"

ThreadGetKeyInfo::ThreadGetKeyInfo()
{
}

ThreadGetKeyInfo::~ThreadGetKeyInfo()
{
}

ThreadGetKeyInfo::ThreadGetKeyInfo( int op, int serverID,
                        MatrixType* data,
                        vector<TYPE_INDEX> &setFreeIdx)
{
    if(op==SEARCH_OPERATION)
        this->lstKey.reserve(MAX_NUM_KEYWORDS);
    else
        this->lstKey.reserve(MAX_NUM_OF_FILES);
    this->lstKey.clear();
    
    this->op = op;
    this->serverID = serverID;
    this->decrypted_data = data;
    this->set_free_idx = setFreeIdx;
 
}
    