#include "struct_threadDataTransmit.h"
#include "DSSE_Param.h"
ThreadDataTransmit::ThreadDataTransmit()
{
    
}
ThreadDataTransmit::~ThreadDataTransmit()
{
    
}
ThreadDataTransmit::ThreadDataTransmit(IndexRequest idx_request, int serverID)
{
    this->idx_request = idx_request;
    this->serverID  = serverID;
    this->search_data = new MatrixType*[NUM_IDX_PER_DIM];
    this->update_data = new MatrixType*[NUM_IDX_PER_DIM];
    for(int k  = 0 ; k < NUM_IDX_PER_DIM; k++)
    {
        this->search_data[k] = new MatrixType[MATRIX_COL_SIZE];
        this->update_data[k] = new MatrixType[MATRIX_ROW_SIZE/BYTE_SIZE];
        
        for(TYPE_INDEX i = 0 ; i < MATRIX_COL_SIZE; i++)
        {
            this->search_data[k][i].byte_data = 0x00;
        }
        for(TYPE_INDEX i = 0 ; i < MATRIX_ROW_SIZE/BYTE_SIZE; i++)
        {
            this->update_data[k][i].byte_data = 0x00;
        }
    }
}