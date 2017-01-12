

#ifndef SERVER_DSSE_H
#define SERVER_DSSE_H

#include <MasterKey.h>
#include <DSSE_Param.h>
#include <struct_MatrixType.h>

#include "struct_IndexRequest.h"
#include <zmq.hpp>
using namespace zmq;
class Server_DSSE
{
private:
    
    // Global & static file counter
	static TYPE_COUNTER gc;

    //Data Structure 
    MatrixType** I;
	int serverID;
    
    MatrixType serialized_data [NUM_IDX_PER_DIM*MATRIX_COL_SIZE + NUM_IDX_PER_DIM*MATRIX_ROW_SIZE/BYTE_SIZE];
    TYPE_INDEX serialized_data_len;
    
    
public:
    Server_DSSE();
    ~Server_DSSE();
    int updateBigMatrix_from_piece(MatrixType** I_big, MatrixType** I_piece, int col_pos);
/*    
    int getBlock_data(int* client_fd);
    int updateBlock_data(int* client_fd);
    int getEncrypted_data_structure(int* client_fd);
    int getEncrypted_file(int * client_fd);
    int searchKeyword(int* client_fd);
    int deleteFile(int * client_fd);
  */  
    int getBlock_data(zmq::socket_t &socket);
    int updateBlock_data(zmq::socket_t &socket);
    int updateEncrypted_data_structure(zmq::socket_t &socket);
    int getEncrypted_file(zmq::socket_t &socket);
    int deleteFile(zmq::socket_t &socket);
    
    
    int start();
};

#endif // SERVER_DSSE_H
