#ifndef PRECOMPUTED_KEY_H
#define PRECOMPUTED_KEY_H
#include <vector>
#include "struct_OperationToken.h"
#include "DSSE_Param.h"
#include "MasterKey.h"
struct ThreadPrecomputedKey
{

    TYPE_INDEX col_idx[NUM_IDX_PER_DIM];
    TYPE_INDEX row_idx[NUM_IDX_PER_DIM];
    TYPE_COUNTER* row_counter_arr;
    TYPE_COUNTER* col_counter_arr;
    
    unsigned char* precomputed_key;
    
    MasterKey *pKey;

    int serverID;
    int op;
    bool genKey_decrypt;
public:
    ThreadPrecomputedKey();
    ThreadPrecomputedKey  (   
                        TYPE_INDEX col_idx[NUM_IDX_PER_DIM],
                        TYPE_INDEX row_idx[NUM_IDX_PER_DIM],
                        int serverID, int op, bool genKey_decrypt,
                        TYPE_COUNTER* row_counter,
                        TYPE_COUNTER* col_counter,
                        MasterKey *pKey);
    ~ThreadPrecomputedKey();
    
};

#endif 