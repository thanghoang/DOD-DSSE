#ifndef STRUCT_THREAD_GETKEY_INFO_H
#define STRUCT_THREAD_GETKEY_INFO_H

#include "DSSE_Hashmap_Key_Class.h"
#include "DSSE_Param.h"

#include "struct_MatrixType.h"
struct ThreadGetKeyInfo
{
    
    vector<TYPE_INDEX> set_free_idx;
    vector<hashmap_key_class> lstKey;
    int op;
    int serverID;
    MatrixType* decrypted_data;
    
    
    
    ThreadGetKeyInfo();
    ThreadGetKeyInfo(int op, int serverID,
                        MatrixType* data,
                        vector<TYPE_INDEX> &setFreeIdx);
    ~ThreadGetKeyInfo();

};

#endif // STRUCT_THREADGETKEYINFO_H
