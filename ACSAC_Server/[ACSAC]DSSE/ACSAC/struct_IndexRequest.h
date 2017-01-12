#ifndef INDEX_REQUEST_H
#define INDEX_REQUEST_H
#include "DSSE_Param.h"
typedef struct IndexRequest
{
    TYPE_INDEX search_idx[NUM_IDX_PER_DIM];
    TYPE_INDEX update_idx[NUM_IDX_PER_DIM];
} INDEX_REQUEST;

#endif