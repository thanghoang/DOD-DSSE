#include "struct_threadCreateNewDataRepresentation.h"

ThreadCreateNewDataRepresentation::ThreadCreateNewDataRepresentation()
{
}

ThreadCreateNewDataRepresentation::~ThreadCreateNewDataRepresentation()
{
}

ThreadCreateNewDataRepresentation::ThreadCreateNewDataRepresentation(vector<hashmap_key_class> &lstKey, int op, int serverID)
{
    this->serverID = serverID;
    this->lstKey = lstKey;
    this->op = op;
    if(op == SEARCH_OPERATION)
    {
        this->data = new MatrixType[MATRIX_COL_SIZE*BYTE_SIZE];
        memset(this->data,0,MATRIX_COL_SIZE*BYTE_SIZE);
    }
    else
    {
        this->data = new MatrixType[MATRIX_ROW_SIZE];
        memset(this->data,0,MATRIX_ROW_SIZE);
    }
}
