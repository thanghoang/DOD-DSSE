
#include "Server_DSSE.h"
#include "DSSE_Param.h"
#include "DSSE_KeyGen.h"

#include "Miscellaneous.h"

#include "DSSE.h"
//#include "net.h"
#include "zmq.hpp"
#include <sys/socket.h>
#include <sys/types.h>
using namespace zmq;
TYPE_COUNTER Server_DSSE::gc = 1;


Server_DSSE::Server_DSSE()
{
    TYPE_INDEX i;
    
    /*
     * 1. Allocate memory for data structure (matrix)
     */
     this->I = new MatrixType *[MATRIX_ROW_SIZE];
     for (i = 0; i < MATRIX_ROW_SIZE;i++ )
     {
         this->I[i] = new MatrixType[MATRIX_COL_SIZE];
     }
     serverID = 0;
     serialized_data_len = NUM_IDX_PER_DIM*MATRIX_COL_SIZE + NUM_IDX_PER_DIM*MATRIX_ROW_SIZE / BYTE_SIZE;
}

Server_DSSE::~Server_DSSE()
{
    
}
int Server_DSSE::start()
{
    int ret;
    unsigned char buffer[SOCKET_BUFFER_SIZE];
    zmq::context_t context(1);
    zmq::socket_t socket(context,ZMQ_REP);
    socket.bind(PEER_ADDRESS_0);
    
    do
    {
        printf("Waiting for request......\n\n");
        while(!socket.connected());
        /*
         * 1. Read the command sent by the client to determine the job
         * */
                
        int cmd;
        socket.recv(buffer,SOCKET_BUFFER_SIZE,ZMQ_RCVBUF);
        

        memcpy(&cmd,buffer,sizeof(cmd));
        printf("REQUESTED......");
        //send back CMD_SUCCESS to the client
        socket.send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
        
        switch(cmd)
        {
        case CMD_SEND_DATA_STRUCTURE:
            printf("\"BUILD DATA STRUCTURE!\"\n");
            if(this->updateEncrypted_data_structure(socket)==0)
                printf("\nDone!\n\n");
            else
                printf("\nError!\n\n");
            break;
        case CMD_ADD_FILE_PHYSICAL:
            printf("\"ADD PHYSICAL ENCRYPTED FILE!\n");
            if(this->getEncrypted_file(socket)==0)
                printf("\nDone!\n\n");
            else
                printf("\nError!\n\n");
            break;
        case CMD_REQUEST_BLOCK_DATA:
            printf("\"GET BLOCK DATA!\"\n");
            if(this->getBlock_data(socket)==0)
                printf("\nDone!\n\n");
            else
                printf("\nError!\n\n");
            break;
        case CMD_UPDATE_BLOCK_DATA:
            printf("\"UPDATE DATA STRUCTURE!\"\n");
            if(this->updateBlock_data(socket)==0)
                printf("\nDone!\n\n");
            else
                printf("\nError!\n\n");
            break;
        case CMD_DELETE_FILE_PHYSICAL:
            printf("\"DELETE FILE PHYSICAL!\"\n");
            if(this->deleteFile(socket)==0)
                printf("\nDone!\n\n");
            else
                printf("\nError!\n\n");
            break;
        default:
            break;
        }
        
    }while(1);

    printf("Server ended \n");
    ret = 0;

    memset(buffer,0,SOCKET_BUFFER_SIZE);
    return ret;
}
//int Server_DSSE::deleteFile(int * client_fd)
int Server_DSSE::deleteFile(zmq::socket_t& socket)
{
    Miscellaneous misc;
    unsigned char buffer_in[SOCKET_BUFFER_SIZE] = {'\0'};
    int ret;
    FILE* foutput = NULL;
    stringstream filename_with_path;
    TYPE_INDEX file_index;
    /*
     * 1. Receive the file index sent by the client
     * */
    printf("1. Receiving file index....");
    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
    
    socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
    
    memcpy(&file_index,buffer_in,sizeof(file_index));
    printf("OK!\n-- Received index: %lu \n",file_index);
    
    printf("2. Deleting the file...");
    
    filename_with_path<<gcsEncFilepath <<"encTar" <<file_index <<".tar.gz";
    if(remove(filename_with_path.str().c_str())!=0)
        printf("Error! File not found...\n");
    //send ACK to client
    //net_send(client_fd,(unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
    socket.send((unsigned char*) CMD_SUCCESS,sizeof(CMD_SUCCESS));
    printf("OK!\n");
    
    ret = 0;
    

    delete foutput;
    filename_with_path.clear();
    memset(buffer_in,0,SOCKET_BUFFER_SIZE);

    return ret;
    
}
int Server_DSSE::updateBlock_data(zmq::socket_t& socket)
{
    Miscellaneous misc;
    DSSE *dsse = new DSSE();
    
    unsigned char buffer_in[SOCKET_BUFFER_SIZE] = {'\0'};
    unsigned char buffer_out[SOCKET_BUFFER_SIZE] = {'\0'};
    int ret,len;
    FILE* foutput = NULL;
    string filename_temp_with_path;
    
    off_t filesize;
    off_t size_received;
    int64_t more;
    size_t more_size = sizeof(more);
    IndexRequest index_request;
    MatrixType* search_data;
    MatrixType* update_data;
    off_t offset;
    TYPE_INDEX n = 0;
    
    
    auto start = time_now;
    auto end = time_now;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start) ;
    double total_time = 0;

    auto start_network = time_now;
    auto end_network = time_now;
    auto elapsed_network = std::chrono::duration_cast<std::chrono::microseconds>(end_network - start_network) ;
    double total_network_time = 0;
    
    /*
     * 1. Receive the block index sent by the client
     * */
    start_network = time_now;
    printf("1.  Receiving IndexRequest token....");
    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
    socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
    
    printf("OK!\n");    
    memcpy(&index_request,buffer_in,sizeof(index_request));
    // send ACK back to client
    socket.send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
    
    end_network = time_now;
    elapsed_network = std::chrono::duration_cast<std::chrono::microseconds>(end_network - start_network) ;
    total_network_time += (double)elapsed_network.count()/(double)1000;
        
    start_network = time_now;
    /*
      * 2. Receive block data sent by the client 
      * */
    offset = 0;
    memset(this->serialized_data,0,this->serialized_data_len);
    while(offset<this->serialized_data_len)
    {
        len=socket.recv(&serialized_data[offset],SOCKET_BUFFER_SIZE,0);
        offset+=len;
        socket.getsockopt(ZMQ_RCVMORE,&more,&more_size);
        if(!more)
            break;
    }
    // Send the ACK
    socket.send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
    
    end_network = time_now;
    elapsed_network = std::chrono::duration_cast<std::chrono::microseconds>(end_network - start_network) ;
    total_network_time += (double)elapsed_network.count()/(double)1000;
    printf("\n---------------------------\n");
    printf("Network delay: %8.4f ms \n",total_network_time);
        
    /* Local processing, update the serialized data into the memory */

    offset = 0;
    start = time_now;
    for(int i = 0 ; i < NUM_IDX_PER_DIM ; i ++)
    {
        dsse->setBlock(index_request.search_idx[i],SEARCH_OPERATION,this->I,&serialized_data[offset]);
        offset+= MATRIX_COL_SIZE;
        dsse->setBlock(index_request.update_idx[i],UPDATE_OPERATION,this->I,&serialized_data[offset]);
        offset+=MATRIX_ROW_SIZE/BYTE_SIZE;
    }
    end = time_now;
    elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    total_time = (double)elapsed.count()/(double)1000;
    printf("Local processing time: %8.4f ms \n",total_time);
        
    
    
    ret = 0;
exit:
    delete dsse;
    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
    memset(buffer_out,0,SOCKET_BUFFER_SIZE);

    filename_temp_with_path.clear();
   
    //close everything to free the memory
    //net_close(*client_fd);
    return ret ; 
}

int Server_DSSE::getBlock_data(zmq::socket_t & socket)
{
    Miscellaneous misc;
    DSSE *dsse = new DSSE();
   
    unsigned char buffer_in[SOCKET_BUFFER_SIZE] = {'\0'};
    unsigned char buffer_out[SOCKET_BUFFER_SIZE] = {'\0'};
    int ret = 0;
    FILE* finput = NULL;
    string filename_temp_with_path;
    
    off_t filesize, offset;
    off_t size_sent;
    TYPE_INDEX n;
    
    IndexRequest index_request;
    
    auto start = time_now;
    auto end = time_now;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start) ;
    double total_time = 0;

    auto start_network = time_now;
    auto end_network = time_now;
    auto elapsed_network = std::chrono::duration_cast<std::chrono::microseconds>(end_network - start_network) ;
    double total_network_time = 0;
    
    
    /*
     * 1. Receive the block index sent by the client
     * */
   
    start_network = time_now;
    printf("1.  Receiving IndexRequest token....");
    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
    socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
    
    printf("OK!\n");
    
    
    memcpy(&index_request,buffer_in,sizeof(index_request));
    // send ACK back to client
    //socket->send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
    
    end_network = time_now;
    elapsed_network = std::chrono::duration_cast<std::chrono::microseconds>(end_network - start_network) ;
    total_network_time += (double)elapsed_network.count()/(double)1000;
    
    /*
     * 2. Get the block requested by the client (LOCAL PROCESSING)
     * */

    memset(this->serialized_data,0,NUM_IDX_PER_DIM*MATRIX_COL_SIZE + NUM_IDX_PER_DIM*MATRIX_ROW_SIZE/BYTE_SIZE);
    start = time_now;
    n = 0;
    for(int i = 0 ; i < NUM_IDX_PER_DIM; i++)
    {
        dsse->getBlock(index_request.search_idx[i],SEARCH_OPERATION,this->I,&this->serialized_data[n]);
        n += MATRIX_COL_SIZE;
        dsse->getBlock(index_request.update_idx[i],UPDATE_OPERATION,this->I,&this->serialized_data[n]);
        n += MATRIX_ROW_SIZE/BYTE_SIZE;
    }
    end = time_now;
    elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start) ;
    total_time = (double) elapsed.count() / (double)1000;
    printf("Local processing time: %8.4f ms \n",total_time);
    start_network = time_now;
    /*
      * 2. Send block data requested by the client 
      * */
    for(offset = 0 ; offset < serialized_data_len; offset +=SOCKET_BUFFER_SIZE)
    {
        //memset(buffer_out,0,SOCKET_BUFFER_SIZE);
        n = (serialized_data_len - offset > SOCKET_BUFFER_SIZE) ? SOCKET_BUFFER_SIZE : (int) 
            (serialized_data_len - offset);
            //memcpy(buffer_out,&search_data[i][offset],n);
            
            if(offset + n == serialized_data_len)
                socket.send(&serialized_data[offset],n,0);
            else
                socket.send(&serialized_data[offset],n,ZMQ_SNDMORE);
    }
    
    // send ACK to client
    //socket.send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
    end_network = time_now;
    elapsed_network = std::chrono::duration_cast<std::chrono::microseconds>(end_network - start_network) ;
    total_network_time += (double)elapsed_network.count()/(double)1000;
    printf("Network delay: %8.4f ms \n",total_network_time);
    
    //close & clear everything to free the memory
    
    ret = 0 ;
exit:
    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
    memset(buffer_out,0,SOCKET_BUFFER_SIZE);
    delete dsse;

    filename_temp_with_path.clear();
    
    return ret ; 
}
int Server_DSSE::updateEncrypted_data_structure(zmq::socket_t& socket)
{
    Miscellaneous misc;
    unsigned char buffer_in[SOCKET_BUFFER_SIZE] = {'\0'};
    int ret, len;
    len = 0;
    FILE* foutput = NULL;
    size_t size_received = 0 ;
    size_t file_in_size;
    MatrixType** I_piece = new MatrixType*[MATRIX_ROW_SIZE];
    int64_t more;
    size_t more_size = sizeof(more);
    string str_i;
    int i;
    
    /*
     * 1. Receive the filename sent by the client
     * */
    printf("1. Receiving file name....");
    
    socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
   
    string filename((char*)buffer_in);
    printf("OK!\t\t\t %s \n",filename.c_str());
    string filename_with_path = gcsDataStructureFilepath + filename;
    /*
    * 2. Open this file
    * */
    printf("2. Opening the file...");
    if((foutput =fopen(filename_with_path.c_str(),"wb+"))==NULL)
    {
        printf("Error! File opened failed!\n");
        ret = FILE_OPEN_ERR;
        goto exit;
    }
    printf("OK!\n");
    /*
     * 1.1 Send OK CMD to the client
     * */
    socket.send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
    /*
     * 1. Receive file content sent by client, write it to the storage 
     * */
    printf("3. Receiving file content");
    
    // 1.1. Receive the file size in bytes first
    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
    socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
    
    memcpy(&file_in_size,buffer_in,sizeof(size_t));
    printf(" of size %zu bytes...",file_in_size);
    
    // Send the ACK to the client
    socket.send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
    
    // 1.2 Receive the file content
    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
    size_received = 0;
    while(size_received<file_in_size)
    {
        len = socket.recv(buffer_in,SOCKET_BUFFER_SIZE,0);
        if(len <0)
        {   
            if(len == REQUEST_TIMEOUT) // if the time out is over, close the session, not yet implemented
            {
                continue;
            }
            else if(len == 0)
            {
                break;
            }
            continue;
        }
        size_received += len;
        if(size_received >= file_in_size)
        {
            fwrite(buffer_in,1,len-(size_received-file_in_size),foutput);
            break;
        }
        else
        {
            fwrite(buffer_in,1,len,foutput);
        }
        socket.getsockopt(ZMQ_RCVMORE,&more,&more_size);
        if(!more)
            break;
    }
    fclose(foutput);
    //send ack to client
    socket.send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
    
    printf("OK!\n\t\t %zu bytes received\n",size_received);
    /*
    * 3. Load the data structure received from the client back to the memory
    * */
    printf("4. Updating memory...");
    str_i = filename.substr(filename.find("-",0)+1,filename.find("_",0));
    i = stoi(str_i);
    cout<<str_i<<endl<<i;
    for(TYPE_INDEX row = 0 ; row < MATRIX_ROW_SIZE; row++)
    {
        I_piece[row] = new MatrixType[MATRIX_PIECE_COL_SIZE];
        memset(I_piece[row],0,MATRIX_PIECE_COL_SIZE);
    }
    misc.read_matrix_from_file(filename,gcsDataStructureFilepath,I_piece,MATRIX_ROW_SIZE,MATRIX_PIECE_COL_SIZE);
    // update the big I
    this->updateBigMatrix_from_piece(this->I,I_piece,i);
    for(TYPE_INDEX row = 0 ; row < MATRIX_ROW_SIZE; row++)
    {
        delete I_piece[row];
    }
    delete I_piece;
    
    printf("OK!\n");
    /*
     * 4. Send OK command back to the client
     * */
    
    /*
     * 5. Close the connection
     * */
    ret = 0;

exit:
    return ret ;
     
}
//int Server_DSSE::getEncrypted_file(int * client_fd)
int Server_DSSE::getEncrypted_file(zmq::socket_t& socket)
{
    Miscellaneous misc;
    unsigned char buffer_in[SOCKET_BUFFER_SIZE] = {'\0'};
    int ret, len;
    len = 0;
    FILE* foutput = NULL;
    size_t size_received = 0 ;
    size_t file_in_size;
    
    int64_t more;
    size_t more_size = sizeof(more);
    
    /*
     * 1. Receive the filename sent by the client
     * */
    printf("1. Receiving file name....");
    //while((len = net_recv(client_fd,buffer_in,SOCKET_BUFFER_SIZE))<0)
    //{
    //    if(len == REQUEST_TIMEOUT)
    //        continue;
    //}
    socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
    
    string filename((char*)buffer_in);
    printf("OK!\t\t\t %s \n",filename.c_str());
    string filename_with_path = gcsEncFilepath + filename;
    
    /*
    * 2. Open this file
    * */
    printf("2. Opening the file...");
    if((foutput =fopen(filename_with_path.c_str(),"wb+"))==NULL)
    {
        printf("Error! File opened failed!\n");
        ret = FILE_OPEN_ERR;
        goto exit;
    }
    printf("OK!\n");
    
    /*
     * 1.1 Send OK CMD to the client
     * */
    //net_send(client_fd,(unsigned char*)CMD_SUCCESS,strlen(CMD_SUCCESS));
    socket.send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
 
    /*
     * 1. Receive file content sent by client, write it to the storage 
     *
     * */
    printf("3. Receiving file content");
    
    // 1.1. Receive the file size in bytes first
    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
    //while((len = net_recv(client_fd,buffer_in,SOCKET_BUFFER_SIZE))<0);
    socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
    
    memcpy(&file_in_size,buffer_in,sizeof(size_t));
    printf(" of size %zu bytes...",file_in_size);
    
    // Send the ACK to the client
    //net_send(client_fd,(unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
    socket.send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
    
    
    // 1.2 Receive the file content
    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
    size_received = 0;
    while(size_received<file_in_size)
    {
        //len = net_recv(client_fd,buffer_in,SOCKET_BUFFER_SIZE);
        len = socket.recv(buffer_in,SOCKET_BUFFER_SIZE,0);
        if(len <0)
        {   
            if(len == REQUEST_TIMEOUT) // if the time out is over, close the session, not yet implemented
            {
                continue;
            }
            else if(len == 0)
            {
                break;
            }
            continue;
        }
        size_received += len;
        if(size_received >= file_in_size)
        {
            fwrite(buffer_in,1,len-(size_received-file_in_size),foutput);
            break;
        }
        else
        {
            fwrite(buffer_in,1,len,foutput);
        }
        socket.getsockopt(ZMQ_RCVMORE,&more,&more_size);
        if(!more)
            break;
    }
    fclose(foutput);
    //send ack to client
    //net_send(client_fd,(unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
    socket.send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
    
    printf("OK!\n\t\t %zu bytes received \n",size_received);
    ret = 0;
    
exit:

    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
    filename_with_path.clear();
    filename.clear();
    
    return ret;
}

int Server_DSSE::updateBigMatrix_from_piece(MatrixType** I_big, MatrixType** I_piece, int col_pos)
{
    int n; 
    TYPE_INDEX col, row, I_big_col_idx;
    Miscellaneous misc;
    n = MATRIX_COL_SIZE/MATRIX_PIECE_COL_SIZE;
    //for(curIdx  = MATRIX_PIECE_COL_SIZE*i; curIdx < MATRIX_PIECE_COL_SIZE * (i+1); curIdx++)
    for(col = 0; col < MATRIX_PIECE_COL_SIZE; col++)
    {
        I_big_col_idx = col+ (col_pos*MATRIX_PIECE_COL_SIZE);
        for(row = 0 ; row < MATRIX_ROW_SIZE ; row++)
        {
            I_big[row][I_big_col_idx].byte_data = I_piece[row][col].byte_data;
        }
    }
}