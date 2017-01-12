#ifndef STRUCT_THREAD_UPDATE_DATA_H
#define STRUCT_THREAD_UPDATE_DATA_H

#include "DSSE_Hashmap_Key_Class.h"
#include "DSSE_Param.h"
#include "struct_MatrixType.h"
struct ThreadCreateNewDataRepresentation
{
    vector<hashmap_key_class> lstKey;
    MatrixType* data;
    int op;
    int serverID;
public:
    ThreadCreateNewDataRepresentation();
    
    ThreadCreateNewDataRepresentation(vector<hashmap_key_class> &lstKey, int op, int serverID);
    ~ThreadCreateNewDataRepresentation();

};

#endif // STRUCT_THREADUPDATEDATASTRUCTURE_H
