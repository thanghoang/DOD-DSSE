#ifndef THREAD_DATA_REQUEST_H
#define THREAD_DATA_REQUEST_H

#include "struct_IndexRequest.h"
#include "struct_MatrixType.h"
typedef struct ThreadDataTransmit
{
    IndexRequest idx_request;
    int serverID;
    MatrixType** search_data;
    MatrixType** update_data;

public:

    ThreadDataTransmit();
    ~ThreadDataTransmit();
    ThreadDataTransmit(IndexRequest idx_request, int serverID);
}THREAD_DATA_TRANSMIT;

#endif 