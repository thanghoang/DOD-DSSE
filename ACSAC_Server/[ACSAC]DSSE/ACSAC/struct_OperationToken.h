#ifndef OPERATION_TOKEN_H
#define OPERATION_TOKEN_H
#include "DSSE_Hashmap_Key_Class.h"
#include "DSSE_Param.h"
typedef struct OperationToken
{
	TYPE_INDEX empty_add[NUM_SERVERS];          //i
    hashmap_key_class nonempty_add[NUM_SERVERS];
    bool b;
    bool isRealQuery;
}OPERATION_TOKEN;

#endif 