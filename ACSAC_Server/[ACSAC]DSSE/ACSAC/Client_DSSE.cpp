#include "Client_DSSE.h"
#include "DSSE_Param.h"
#include "DSSE_KeyGen.h"
#include "string.h"
#include <sstream>	
#include "Miscellaneous.h"

#include "DSSE.h"



// Hash map where the trapdoors for the keywords are stored
TYPE_GOOGLE_DENSE_HASH_MAP Client_DSSE::T_W;

	// Static hash map where the trapdoors for the files are stored
TYPE_GOOGLE_DENSE_HASH_MAP Client_DSSE::T_F;
TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX Client_DSSE::T_W_IDX[NUM_SERVERS];
TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX Client_DSSE::T_F_IDX[NUM_SERVERS];

unsigned char Client_DSSE::precomputed_row_key[NUM_SERVERS][MATRIX_ROW_SIZE*BLOCK_CIPHER_SIZE];
vector<TYPE_INDEX> Client_DSSE::lstT_W_IDX[NUM_SERVERS];
vector<TYPE_INDEX> Client_DSSE::lstT_F_IDX[NUM_SERVERS];
vector<vector<TYPE_INDEX>> Client_DSSE::kw_file_pair[NUM_SERVERS];


#if defined (CLIENT_SERVER_MODE)

#include "zmq.hpp"
using namespace zmq;
using namespace std;
#include "net.h"
#endif

TYPE_COUNTER Client_DSSE::gc = 1;


TYPE_KEYWORD_DICTIONARY Client_DSSE::keywords_dictionary;

Client_DSSE::Client_DSSE()
{
    TYPE_INDEX i;
    /*
     * 0. Allocate memory for key and some security parameters
     */
    data_structure_constructed = false;
    
    for(i = 0 ; i <BLOCK_CIPHER_SIZE;i++)
    {
        this->extractor_salt[i] = 0;
        this->pseudo_random_key[i] = 0;
    }
    
    /* ACSAC */
    // Init the set of all available row indices and column indices
    for(int i = 0 ; i <NUM_SERVERS; i ++)
    {
        for(TYPE_INDEX j = 0 ; j < MATRIX_COL_SIZE*BYTE_SIZE; j++)
            setFileIdx[i].push_back(j);
        for (TYPE_INDEX j = 0 ; j < MATRIX_ROW_SIZE; j++)
            setKeywordIdx[i].push_back(j);        
    }

    this->SERVER_ADDRESS[0] = PEER_ADDRESS_0;
    this->SERVER_ADDRESS[1] = PEER_ADDRESS_1;
#if defined (CLIENT_SERVER_MODE)
    serialized_data_len = NUM_IDX_PER_DIM* MATRIX_COL_SIZE + NUM_IDX_PER_DIM*MATRIX_ROW_SIZE/BYTE_SIZE;
#endif
}

Client_DSSE::~Client_DSSE()
{
    
}
int Client_DSSE::genMaster_key()
{
    DSSE_KeyGen *dsse_key = new DSSE_KeyGen();
    Miscellaneous misc;
    string key_loc;
    this->masterKey = new MasterKey();
    int ret;
#if !defined(LOAD_PREVIOUS_DATA_MODE)
    if((ret = dsse_key->genMaster_key(this->masterKey,this->pseudo_random_key,BLOCK_CIPHER_SIZE,this->extractor_salt,BLOCK_CIPHER_SIZE,this->pseudo_random_key,BLOCK_CIPHER_SIZE))!=0)
    {
        printf("Key generation error!");
        ret = KEY_GENERATION_ERR;
        delete this->masterKey;
        goto exit;
    }
    //write keys to file
    key_loc = gcsDataStructureFilepath + "key1";
    misc.write_file_cpp(key_loc,this->masterKey->key1,BLOCK_CIPHER_SIZE);
    
    key_loc = gcsDataStructureFilepath + "key2";
    misc.write_file_cpp(key_loc,this->masterKey->key2,BLOCK_CIPHER_SIZE);
    
    
    for(int k = 0 ; k < NUM_SERVERS; k++)
    {
        key_loc = gcsDataStructureFilepath + "key3" + std::to_string(k);
        misc.write_file_cpp(key_loc,this->masterKey->key3[k],BLOCK_CIPHER_SIZE);
    }
#else //load key from file
    
    key_loc = gcsDataStructureFilepath + "key1";
    misc.read_file_cpp(this->masterKey->key1,BLOCK_CIPHER_SIZE,key_loc);
    
    key_loc = gcsDataStructureFilepath + "key2";
    misc.read_file_cpp(this->masterKey->key2,BLOCK_CIPHER_SIZE,key_loc);
    
     for(int k = 0 ; k < NUM_SERVERS; k++)
    {
        key_loc = gcsDataStructureFilepath + "key3" + std::to_string(k);
        misc.read_file_cpp(this->masterKey->key3[k],BLOCK_CIPHER_SIZE,key_loc);
    }
    
#endif
    ret = 0;

exit:

    data_structure_constructed = false;
    delete dsse_key;
    
    return ret;
}

#if defined(CLIENT_SERVER_MODE)
int Client_DSSE::sendFile(string filename, string path, int SENDING_TYPE, int serverID)
{
    int ret;
    int n; //n : number of block read from file
    
    FILE* finput = NULL;
    unsigned char buffer_in[SOCKET_BUFFER_SIZE];
	unsigned char buffer_out[SOCKET_BUFFER_SIZE];
	
    off_t filesize, offset;
    off_t size_sent = 0;
    string filename_with_path = path + filename;
    
    zmq::context_t context(1);
    zmq::socket_t socket(context,ZMQ_REQ);
    
    /*
     * 1. Open the file need to be sent
     * */
    try
    {
        printf("   Opening file...");
        if( ( finput = fopen(filename_with_path.c_str(), "rb" ) ) == NULL )
        {
            printf( "Error! File not found \n" );
            ret = FILE_OPEN_ERR;
            goto exit;
        }
        /*
         * 2. Determine the file size
         * 
         * */
        if( ( filesize = lseek( fileno( finput ), 0, SEEK_END ) ) < 0 )
        {
            perror( "lseek" );
            ret = FILE_OPEN_ERR;
            goto exit;
        }
        
        if( fseek( finput, 0, SEEK_SET ) < 0 )
        {
            printf("fseek(0,SEEK_SET) failed\n" );
            ret = FILE_OPEN_ERR;
            goto exit;
        }
        printf("OK!\n");
        /*
         * 3. Connect to the server
         * 
         * */
        printf("   Connecting to server...");
        socket.connect (this->SERVER_ADDRESS[serverID].c_str());
        printf("connected!\n");
        /*
         * 5. Send the command first to the server so that the server can know what the client intends to do
         * */
        printf("   Sending file sending command...");
        
        memset(buffer_out,0,SOCKET_BUFFER_SIZE);
        memcpy(buffer_out,&SENDING_TYPE,sizeof(SENDING_TYPE));
        
        socket.send(buffer_out,SOCKET_BUFFER_SIZE);
        
        // Wait the server to response before continue
        socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
        printf("OK!\n");
        
        /*
         * 6. Send the filename first to the server
         * */
        printf("   Sending file name...");
        socket.send((unsigned char*) filename.c_str(),strlen(filename.c_str()));
        printf("OK!\n");
        // Wait the server response before continuing to send
        socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
        
        /*
         * 6. Send the content of the file to the server block by block
         * */
        printf("   Sending file data...");
        // 6.1. Send the size of the file in byte first
        memset(buffer_out,0,SOCKET_BUFFER_SIZE);
        memcpy(buffer_out,&filesize,sizeof(size_t));
        
        socket.send(buffer_out,SOCKET_BUFFER_SIZE);
        
        // Receive ACK from server
        socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
        // 6.2 Read file block by block and write to the destination
        size_sent = 0;
        for( offset = 0; offset < filesize; offset += SOCKET_BUFFER_SIZE )
        {
            n = ( filesize - offset > SOCKET_BUFFER_SIZE ) ? SOCKET_BUFFER_SIZE : (int)
                ( filesize - offset );
            if( fread( buffer_in, 1, n, finput ) != (size_t) n )
            {
                printf( "read input file error at block %d",n);
                break;
            }
            
            //write to the server
            if(offset + n ==filesize)
                socket.send(buffer_in,n,0);
            else
                socket.send(buffer_in,n,ZMQ_SNDMORE);
            
            size_sent += n;
            if(size_sent % 10485760 == 0)
            {
                printf("%jd / %jd sent \n",size_sent,filesize);
            }
        }
        fclose(finput);
        //wait ACK's server;
        socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
        printf("OK!\t\t\t %jd bytes sent\n",size_sent);
    }
    catch (exception &ex)
    {
        ret = CLIENT_SEND_FILE_ERR;
        goto exit;
    }
    
    /*
     * 7. End the sessions, close the connection
     * 
     * */
    ret = 0;
exit:

    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
	memset(buffer_out,0,SOCKET_BUFFER_SIZE);
    socket.disconnect(this->SERVER_ADDRESS[serverID].c_str());
    socket.close();
    return ret;
    
}
#endif
int Client_DSSE::createEncrypted_data_structure()
{
   /*
    * 1. Encrypt the data structure locally
    * 
    * */
    DSSE* dsse = new DSSE();
    int ret;
    TYPE_INDEX i;
    vector<string> files_input;
#if defined(CLIENT_SERVER_MODE)

#if defined(ENCRYPT_PHYSICAL_FILE)
    vector<string> sending_files;
#endif
    Miscellaneous misc;
#endif
    
    try
    {
        printf("0. Allocating memory for data structure......");
        /*
         * 0.1. Allocate memory for data structure I
         */
           
        for(int i = 0 ; i < NUM_SERVERS ; i++)
        {
            lstT_W_IDX[i].reserve(MATRIX_ROW_SIZE);
            lstT_F_IDX[i].reserve(MATRIX_COL_SIZE*BYTE_SIZE);
        }
#if !defined (CLIENT_SERVER_MODE)
         for (int k = 0 ; k <NUM_SERVERS; k++)
         {
             this->I[k] = new MatrixType *[MATRIX_ROW_SIZE];
             for (i = 0; i < MATRIX_ROW_SIZE;i++ )
             {
                 this->I[k][i] = new MatrixType[MATRIX_COL_SIZE];
             }
         }
#endif
        for(int k = 0 ; k < NUM_SERVERS; k ++)
        {
             this->column_counter_arr[k] = new TYPE_COUNTER[MATRIX_COL_SIZE*BYTE_SIZE];
             this->row_counter_arr[k] = new TYPE_COUNTER[MATRIX_ROW_SIZE];
            Client_DSSE::kw_file_pair[k].reserve(MATRIX_COL_SIZE*BYTE_SIZE);
            for(TYPE_INDEX col = 0 ; col < MATRIX_COL_SIZE*BYTE_SIZE; col++)
            {
                vector<TYPE_INDEX> tmp;
                Client_DSSE::kw_file_pair[k].push_back(tmp);
            }
            /*
             * 3.a Initiate the counter value to value of 1 for all files and keywords
             * */
            for(TYPE_INDEX row = 0 ; row<MATRIX_ROW_SIZE; row++)
            {
                this->row_counter_arr[k][row] = ONE_VALUE;
                
            }
            for(TYPE_INDEX col = 0 ; col < MATRIX_COL_SIZE*BYTE_SIZE; col++)
            {
                this->column_counter_arr[k][col] = ONE_VALUE;
            }
        
        }
        
        files_input.reserve(MAX_NUM_OF_FILES);
        printf("1. Setting up data structure......\n");
        if((ret = dsse->setupData_structure(  this->I,this->T_W,this->T_F,this->T_W_IDX,this->T_F_IDX,
                                    this->setKeywordIdx,this->setFileIdx,
                                    this->row_counter_arr, this->column_counter_arr,
                                    files_input,gcsFilepath,gcsEncFilepath,
                                    this->masterKey,this->keywords_dictionary))!=0)
        {
            goto exit;
        }
        printf("\nFinished!\n");
        printf("Size of keyword hash table: \t\t\t %zu \n",this->T_W.bucket_count());
        printf("Load factor of keyword hash table: \t\t %3.10f \n",this->T_W.load_factor());
        printf("# keywords extracted: \t\t\t\t %5.0f \n",this->T_W.load_factor()*T_W.bucket_count());
        printf("# distinct keywords: \t\t\t\t %zu \n\n",this->keywords_dictionary.size());
        printf("Size of file hash table: \t\t\t %zu \n",this->T_F.bucket_count());
        printf("Load factor of file hash table: \t\t %3.10f \n",this->T_F.load_factor());
        printf("# files extracted: \t\t\t\t %5.0f \n",this->T_F.load_factor()*T_F.bucket_count());
        
        
        
#if defined(CLIENT_SERVER_MODE)

#if !defined(UPLOAD_DATA_STRUCTURE_MANUALLY_MODE)
        /*
         * 2. Write I to the file
         * 
         * */
        //I
        for(int k = 0 ; k < NUM_SERVERS; k++)
        {
            printf("Server %d...",k);
            printf("Sending data structure to server %d...\n",k);
            int n = MATRIX_COL_SIZE / MATRIX_PIECE_COL_SIZE;
            for(int i = 0 ; i <  n ;i++)
            {
                string filename = std::to_string(k)+ "-" +  std::to_string(i) ;
                this->sendFile(filename,gcsMatrixPiece,CMD_SEND_DATA_STRUCTURE,k);
            }
        }
#else
    printf("Please copy generated data structure to server before continue...");
    cin.get();
    
#endif
#if defined(ENCRYPT_PHYSICAL_FILE)
        /*
         * 4. Send encrypted physical files to the server
         * 
         * */
        printf("4. Sending encrypted files...\n");
        sending_files.clear();
        
        misc.extract_file_names(sending_files, gcsEncFilepath);	
        
        for( i = 0;  i < sending_files.size();i++ )
        {
            printf("%lu / %zu \n",i,sending_files.size());
            if((ret = this->sendFile(sending_files[i],gcsEncFilepath,CMD_ADD_FILE_PHYSICAL))!=0)
            {
                goto exit;
            }
        }
#endif
#endif
    }
    catch (exception &ex)
    {
        ret = CLIENT_CREATE_DATA_STRUCTURE_ERR;
        goto exit;
    }
    /*
     * 5. Done, clear everything
     * */
    data_structure_constructed = true;
    ret =0;
exit:

#if defined(CLIENT_SERVER_MODE)

#if defined (ENCRYPT_PHYSICAL_FILE)
    sending_files.clear();
#endif

#endif    
    files_input.clear();
    delete dsse;
    return ret;
     
}

int Client_DSSE::bit_field_reset(MatrixType *I,
		TYPE_INDEX col,
		int bit_position)
{
    int ret;
	try
    {
        switch(bit_position){

        case 0: I[col].bit_data.bit1 = 0;
        break;

        case 1: I[col].bit_data.bit2 = 0;
        break;

        case 2: I[col].bit_data.bit3 = 0;
        break;

        case 3: I[col].bit_data.bit4 = 0;
        break;

        case 4: I[col].bit_data.bit5 = 0;
        break;

        case 5: I[col].bit_data.bit6 = 0;
        break;

        case 6: I[col].bit_data.bit7 = 0;
        break;

        case 7: I[col].bit_data.bit8 = 0;
        break;

        default:
            cout << "Error : Invalid bit number";
            ret = INVALID_BIT_NUMBER_ERR;
            goto exit;
            break;
        }
    }
    catch(exception &e)
    {
        cout << "Error occured in bit_field_access function " << e.what() << endl;
        ret = BIT_FIELD_ACCESS_ERR;
        goto exit;
    }
    ret = 0; 
exit:
	return ret;
}

int Client_DSSE::operation(int op, string strInput)        //CHANGE LATER PARAMETER
{
    int ret;
    string keyword = "the";

    int b, negb;

    MatrixType *search_decrypted_b[NUM_SERVERS];
    MatrixType *update_decrypted_b[NUM_SERVERS];
    
    
    MatrixType **search_data[NUM_SERVERS];
    MatrixType **update_data[NUM_SERVERS];
    DSSE* dsse = new DSSE();
    OPERATION_TOKEN searchToken, updateToken;
    
    TYPE_INDEX search_idx, update_idx;
    Miscellaneous misc;
    
    TYPE_GOOGLE_DENSE_HASH_MAP::iterator it;
    
    auto start = time_now;
    auto end = time_now;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start) ;
    double total_time = 0;
    
    
#if defined(CLIENT_SERVER_MODE)
    
    
    int len;
    //int server_fd =1;
    unsigned char buffer_in[SOCKET_BUFFER_SIZE] = {'\0'};
	unsigned char buffer_out[SOCKET_BUFFER_SIZE] = {'\0'};
    zmq::context_t context(1);
    zmq::socket_t socket (context,ZMQ_REQ);
    int cmd;
    auto start_network = std::chrono::system_clock::now();
    auto end_network = std::chrono::system_clock::now();
    auto elapsed_network = std::chrono::duration_cast<std::chrono::microseconds> (end_network - start_network);
    double total_network_time = 0;    
#endif
    
    
    // 2. Prepare NUM_SERVERS * 8 arrays to receive 8 data blocks read from 2 servers.
    for (int k = 0 ; k < NUM_SERVERS; k++)
    {
        
        search_decrypted_b[k] = new MatrixType[MATRIX_COL_SIZE];
        for(TYPE_INDEX i = 0 ; i <MATRIX_COL_SIZE; i++)
        {
            search_decrypted_b[k][i].byte_data = 0x00;
        }
            
        update_decrypted_b[k] = new MatrixType[MATRIX_ROW_SIZE/BYTE_SIZE]; 
        
        for(TYPE_INDEX i = 0 ; i <MATRIX_ROW_SIZE/BYTE_SIZE; i++)
        {
            update_decrypted_b[k][i].byte_data = 0x00;
        }   
        search_data[k] = new MatrixType*[NUM_IDX_PER_DIM];
        update_data[k] = new MatrixType*[NUM_IDX_PER_DIM];
        
        for(int i = 0 ; i < NUM_IDX_PER_DIM; i++)
        {
            search_data[k][i] = new MatrixType[MATRIX_COL_SIZE];
            update_data[k][i] = new MatrixType[MATRIX_ROW_SIZE/BYTE_SIZE];
            for(TYPE_INDEX j = 0 ; j < MATRIX_COL_SIZE; j++)
                search_data[k][i][j].byte_data = 0x00;
            for(TYPE_INDEX j = 0 ; j < MATRIX_ROW_SIZE/BYTE_SIZE; j++)
                update_data[k][i][j].byte_data = 0x00;
        }
    }
    /* 
     * 1. Generate the token for search & update query
     */
     start = time_now;
    if(op == SEARCH_OPERATION)
    {
        dsse->genToken(searchToken,op,strInput,this->setKeywordIdx,this->T_W,this->masterKey);
        dsse->genToken(updateToken,UPDATE_OPERATION,"",this->setFileIdx,this->T_F,this->masterKey);
        b = searchToken.b;
        negb = (b+1) % 2;
    }
    else
    {
        dsse->genToken(updateToken,op,strInput,this->setFileIdx,this->T_F,this->masterKey);
        dsse->genToken(searchToken,SEARCH_OPERATION,"",this->setKeywordIdx,this->T_W,this->masterKey);
        b = updateToken.b;
        negb = (b+1) % 2;
    }
    end = time_now;
    cout<<"\n GENERATE SEARCH & UPDATE TOKENS: "<<std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()/1000000.0<<endl ;
#if defined(CLIENT_SERVER_MODE)
    
    /* 
     * CREATE 8 threads to precompute decryption (2) & reencryption keys (2) for 2 servers
     * */
     start = time_now;
    for(int k = 0 ; k < NUM_SERVERS ; k++)
    {
        
        update_idx_arr[k][1] = this->T_F[updateToken.nonempty_add[k]]->getIndexBySID(k);
        update_idx_arr[k][0] = updateToken.empty_add[k];
        search_idx_arr[k][1] =  this->T_W[searchToken.nonempty_add[k]]->getIndexBySID(k);
        search_idx_arr[k][0] = searchToken.empty_add[k];
        
        //deryption key
        //search...
        key_decrypt_search_param[k]  = new ThreadPrecomputedKey(update_idx_arr[k],search_idx_arr[k],k,SEARCH_OPERATION,true,this->row_counter_arr[k],this->column_counter_arr[k],this->masterKey);
        pthread_create(&thread_key_decrypt_search[k],NULL,&Client_DSSE::thread_precomputed_key_func,(void*)key_decrypt_search_param[k]);
        
        //update...
        key_decrypt_update_param[k]  = new ThreadPrecomputedKey(update_idx_arr[k],search_idx_arr[k],k,UPDATE_OPERATION,true,this->row_counter_arr[k],this->column_counter_arr[k],this->masterKey);
        pthread_create(&thread_key_decrypt_update[k],NULL,&Client_DSSE::thread_precomputed_key_func,(void*)key_decrypt_update_param[k]);
        
        //reencryption key
        //search...
        
        key_reencrypt_search_param[k]  = new ThreadPrecomputedKey(update_idx_arr[k],search_idx_arr[k],k,SEARCH_OPERATION,false,this->row_counter_arr[k],this->column_counter_arr[k],this->masterKey);
        pthread_create(&thread_key_reencrypt_search[k],NULL,&Client_DSSE::thread_precomputed_key_func,(void*)key_reencrypt_search_param[k]);
        //update...
        key_reencrypt_update_param[k]  = new ThreadPrecomputedKey(update_idx_arr[k],search_idx_arr[k],k,UPDATE_OPERATION,false,this->row_counter_arr[k],this->column_counter_arr[k],this->masterKey);
        pthread_create(&thread_key_reencrypt_update[k],NULL,&Client_DSSE::thread_precomputed_key_func,(void*)key_reencrypt_update_param[k]);
        
    }
    /* 
     * Create 2 threads to receive data from 2 servers 
     * */
     
     for(int k = 0 ; k < NUM_SERVERS;k++)
     {
        idx_request[k].search_idx[0] = searchToken.empty_add[k];
        idx_request[k].search_idx[1] = this->T_W[searchToken.nonempty_add[k]]->getIndexBySID(k);
        idx_request[k].update_idx[0] = updateToken.empty_add[k];
        idx_request[k].update_idx[1] = this->T_F[updateToken.nonempty_add[k]]->getIndexBySID(k);
        
        data_transmit[k] = new ThreadDataTransmit(idx_request[k],k);
        pthread_create(&thread_requestData[k],NULL,&Client_DSSE::thread_requestBlock_data,(void*)data_transmit[k]);
    
     }
    for(int k = 0 ; k < NUM_SERVERS; k++)
    {
        pthread_join( thread_key_decrypt_search[k], NULL);
        
        pthread_join( thread_key_decrypt_update[k], NULL);
    
        pthread_join( thread_key_reencrypt_search[k], NULL);
        
        pthread_join( thread_key_reencrypt_update[k], NULL);
        
        pthread_join(thread_requestData[k],NULL);
    }
    end = time_now;
    cout<<"\n DOWNLOAD & PRECOMPUTE TIME: "<<std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()/1000000.0<<endl ;
    /* 
     * 4. Decrypt read data
     * */
    start = time_now;
    for (int k = 0 ; k < NUM_SERVERS ; k++)
    {
        //search
        //dsse->enc_decBlock_with_preAESKey(data_transmit[k]->search_data[1], SEARCH_OPERATION, precomputed_key_param[k]->key_search_decrypt,search_decrypted_b[k]);
        dsse->enc_decBlock_with_preAESKey(data_transmit[k]->search_data[1], SEARCH_OPERATION, key_decrypt_search_param[k]->precomputed_key,search_decrypted_b[k]);
        
        //update
        dsse->enc_decBlock_with_preAESKey(data_transmit[k]->update_data[1],UPDATE_OPERATION,key_decrypt_update_param[k]->precomputed_key,update_decrypted_b[k]);
    }
    end = time_now;
    cout<<"\n DECRYPT TIME: "<<std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()/1000000.0<<endl ;
    
#else // LOCAL PROCESSING
    
    /*
     * 3. Get block data & decrypt it
     * */
    for (int k = 0 ; k < NUM_SERVERS ; k++)
    {
        //search
        dsse->getBlock(searchToken.empty_add[k],SEARCH_OPERATION,this->I[k],search_data[k][0]);
        search_idx = this->T_W[searchToken.nonempty_add[k]]->getIndexBySID(k);
        dsse->getBlock(search_idx,SEARCH_OPERATION,this->I[k],search_data[k][1]);
        
        dsse->decBlock(search_data[k][1],SEARCH_OPERATION,k,search_idx,this->row_counter_arr[k][search_idx],this->column_counter_arr[k],search_decrypted_b[k],this->T_F_IDX[k],this->masterKey);
        
        //update
        dsse->getBlock(updateToken.empty_add[k],UPDATE_OPERATION,this->I[k],update_data[k][0]);
        update_idx = this->T_F[updateToken.nonempty_add[k]]->getIndexBySID(k);
        dsse->getBlock(update_idx,UPDATE_OPERATION,this->I[k],update_data[k][1]);
        
        dsse->decBlock(update_data[k][1],UPDATE_OPERATION,k,update_idx,this->column_counter_arr[k][update_idx],this->row_counter_arr[k],update_decrypted_b[k],this->T_W_IDX[k],this->masterKey);

    }
    end = time_now;
    cout<<"\n GET BLOCK TIME: "<<std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()/1000000.0<<endl ;
#endif
    
    /*
     * 5. Get Key info
     * */
    start = time_now;
    for(int k = 0 ; k < NUM_SERVERS; k++)
    {
        //search
        key_info_search_param[k] = new ThreadGetKeyInfo(SEARCH_OPERATION,k,search_decrypted_b[k],this->setFileIdx[k]);
        pthread_create(&thread_key_info_search[k],NULL,&Client_DSSE::thread_getKey_info_func,(void*)key_info_search_param[k]);
        
        
        //update
        key_info_update_param[k] = new ThreadGetKeyInfo(UPDATE_OPERATION,k,update_decrypted_b[k],this->setKeywordIdx[k]);
        pthread_create(&thread_key_info_update[k],NULL,&Client_DSSE::thread_getKey_info_func,(void*)key_info_update_param[k]);
   
    
    }
    start = time_now;
    for(int k = 0 ; k < NUM_SERVERS; k++)
    {
        pthread_join(thread_key_info_update[k],NULL);
        pthread_join(thread_key_info_search[k],NULL);
        
    }
    end  = time_now;
    cout<<"\n GET KEY INFO TIME: "<<std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()/1000000.0<<endl ;
    cin.get();
        
    //store the old address in order to fast re-update the decrypted data
    TYPE_INDEX nonempty_add_col[NUM_SERVERS];
    TYPE_INDEX nonempty_add_row[NUM_SERVERS];
    
    for(int k = 0 ; k < NUM_SERVERS ; k++)
    {
        int negk = (k+1) %2 ;
        nonempty_add_col[k] = this->T_F[updateToken.nonempty_add[negk]]->getIndexBySID(k);
        nonempty_add_row[k] = this->T_W[searchToken.nonempty_add[negk]]->getIndexBySID(k);
    }
    
    /*
     * 5. UpdateT including the new address of read data, free addresses and row keys
     * */
    
    // search
    start = time_now;
    

    dsse->updateT(searchToken,this->setKeywordIdx,this->row_counter_arr,this->T_W,this->T_W_IDX,Client_DSSE::lstT_W_IDX);
    // update
    dsse->updateT(updateToken,this->setFileIdx,this->column_counter_arr,this->T_F,this->T_F_IDX,Client_DSSE::lstT_F_IDX);
    for(int k = 0 ; k < NUM_SERVERS ; k++)
    {
        dsse->updateRow_key(row_counter_arr[k],k,this->T_W[searchToken.nonempty_add[k]]->getIndexBySID(k),Client_DSSE::precomputed_row_key[k],this->masterKey);
        dsse->updateRow_key(row_counter_arr[k],k,searchToken.empty_add[k],Client_DSSE::precomputed_row_key[k],this->masterKey);
    }
    end = time_now;
    cout<<"\n UPDATE T TIME: "<<std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count()/1000000.0<< " ms"<<endl;
    if(op==SEARCH_OPERATION)
    {
        if(searchToken.isRealQuery)
        {
            cout<<"\nserver ID: "<<b<<endl<<"row index: "<<this->T_W[searchToken.nonempty_add[b]]->getIndexBySID(b)<<endl<<"result: ";
            cout<<key_info_search_param[b]->lstKey.size()<<endl;
            cout<<"S{negb} index: "<<searchToken.empty_add[negb]<<endl;
            cin.get();
            /*
            for(TYPE_INDEX i = 0 ; i < lstSearch_key[b].size(); i++)
            {
                misc.print_ucharstring(lstSearch_key[b][i].get_data(),TRAPDOOR_SIZE);
                cout<<"  "<<this->T_F[lstSearch_key[b][i]]->getIndexBySID(b)<<endl;
            }
             */
        }
        else
        {
            cout<<"keyword does not exist";
        }
    }
    else
    {
        dsse->genUpdate_lstKey_from_file(strInput,op,key_info_update_param[updateToken.b]->lstKey,this->T_W,this->setKeywordIdx,this->masterKey);
    }
    /*
     * 6.0 Create the new data representation appropriate with the position map in the other server
     * */
    start = time_now;
    for(int k = 0 ; k < NUM_SERVERS; k++)
    {
        int negk =  (k +1) %2;
        //search
        dsse->updateBlock(search_decrypted_b[k],updateToken.empty_add[k],nonempty_add_col[k]);
        
        new_data_representation_search_param[negk] = new ThreadCreateNewDataRepresentation(key_info_search_param[k]->lstKey,SEARCH_OPERATION,negk);
        pthread_create(&thread_new_data_representation_search[k],NULL,&Client_DSSE::thread_createNew_data_representation_func,(void*)new_data_representation_search_param[negk]);
        
        //update
        dsse->updateBlock(update_decrypted_b[k],searchToken.empty_add[k],nonempty_add_row[k]);
        new_data_representation_update_param[negk] = new ThreadCreateNewDataRepresentation(key_info_update_param[k]->lstKey,UPDATE_OPERATION,negk);
        pthread_create(&thread_new_data_representation_update[k],NULL,&Client_DSSE::thread_createNew_data_representation_func,(void*)new_data_representation_update_param[negk]);
      
    }
    for(int k = 0 ; k < NUM_SERVERS;k++)
    {
        pthread_join(thread_new_data_representation_search[k],NULL);
        pthread_join(thread_new_data_representation_update[k],NULL);
    }
    end = time_now;
    cout<<"\n CREATE NEW DATA REPRESENTATION TIME: "<<std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()/1000000.0<<endl ;
    
#if defined (CLIENT_SERVER_MODE)
    /* 
     * 6. Re-encrypt data
     * */
    start = time_now;
    for(int k = 0 ; k < NUM_SERVERS; k++)
    {
        // search
        dsse->enc_decBlock_with_preAESKey(search_decrypted_b[k],SEARCH_OPERATION,&key_reencrypt_search_param[k]->precomputed_key[0],data_transmit[k]->search_data[1]);
        dsse->enc_decBlock_with_preAESKey(new_data_representation_search_param[k]->data,SEARCH_OPERATION,&key_reencrypt_search_param[k]->precomputed_key[MATRIX_COL_SIZE],data_transmit[k]->search_data[0]);
        
        // update
        dsse->enc_decBlock_with_preAESKey(update_decrypted_b[k],UPDATE_OPERATION,&key_reencrypt_update_param[k]->precomputed_key[0],data_transmit[k]->update_data[1]);
        dsse->enc_decBlock_with_preAESKey(new_data_representation_update_param[k]->data,UPDATE_OPERATION,&key_reencrypt_update_param[k]->precomputed_key[MATRIX_ROW_SIZE/BYTE_SIZE],data_transmit[k]->update_data[0]);    
    }
    end = time_now;
    cout<<"\n REENCRYPTION TIME: "<<std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()/1000000.0<<endl ;
    
    /* 
     * 7. Put/update encrypted data back to the original data structure
     * */
    start = time_now;
    for(int k = 0 ; k < NUM_SERVERS;k++)
    {
        pthread_create(&thread_uploadData[k],NULL,&Client_DSSE::thread_uploadBlock_data,(void*)data_transmit[k]);
    
    }
    for(int k = 0 ; k < NUM_SERVERS; k++)
    {
        pthread_join(thread_uploadData[k],NULL);
    }
    end = time_now;
    cout<<"\n UPLOAD BLOCK TIME: "<<std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()/1000000.0<<endl ;
    
#else // LOCAL PROCESSING
    /* 
     * 6. Re-encrypt data
     * */
    start = time_now;
    for(int k = 0 ; k < NUM_SERVERS; k++)
    {
        // search
        search_idx = this->T_W[searchToken.nonempty_add[k]]->getIndexBySID(k);        
        dsse->encBlock(search_decrypted_b[k],SEARCH_OPERATION,k,search_idx,this->row_counter_arr[k][search_idx],this->column_counter_arr[k],search_data[k][1],this->masterKey);
        search_idx = searchToken.empty_add[k];
        dsse->encBlock(search_decrypted_negb[k],SEARCH_OPERATION,k,search_idx,this->row_counter_arr[k][search_idx],this->column_counter_arr[k],search_data[k][0],this->masterKey);

        // update
        update_idx = this->T_F[updateToken.nonempty_add[k]]->getIndexBySID(k);
        dsse->encBlock(update_decrypted_b[k],UPDATE_OPERATION,k,update_idx,this->column_counter_arr[k][update_idx],this->row_counter_arr[k],update_data[k][1],this->masterKey);
        update_idx = updateToken.empty_add[k];
        dsse->encBlock(update_decrypted_negb[k],UPDATE_OPERATION,k,update_idx,this->column_counter_arr[k][update_idx],this->row_counter_arr[k],update_data[k][0],this->masterKey);
    }
    end = time_now;
    cout<<"\nReencryption time: "<<std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()/1000000.0<<endl ;
    
    start = time_now;
    for(int k = 0 ; k <NUM_SERVERS ; k ++)
    {
        //search
        dsse->setBlock(searchToken.empty_add[k],SEARCH_OPERATION,this->I[k],search_data[k][0]);
        search_idx = this->T_W[searchToken.nonempty_add[k]]->getIndexBySID(k);
        dsse->setBlock(search_idx,SEARCH_OPERATION,this->I[k],search_data[k][1]);
        
        //update
        dsse->setBlock(updateToken.empty_add[k],UPDATE_OPERATION,this->I[k],update_data[k][0]);
        update_idx = this->T_F[updateToken.nonempty_add[k]]->getIndexBySID(k);
        dsse->setBlock(update_idx,UPDATE_OPERATION,this->I[k],update_data[k][1]);
    }
    end = time_now;
    cout<<"\n Update Block time: "<<std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()/1000000.0<<endl ;
#endif
    ret = 0;
    
exit:

    for (int k = 0 ; k < NUM_SERVERS; k++)
    {
        //delete precomputed_key_param[k];
        delete search_decrypted_b[k];
        delete update_decrypted_b[k];   
    }
    return ret;
}
#if defined(CLIENT_SERVER_MODE)
int Client_DSSE::requestBlock_data(IndexRequest index_request, int serverID,MatrixType** search_data, MatrixType **update_data)
{
    int cmd;
    Miscellaneous misc;
    FILE* foutput = NULL;
    unsigned char buffer_in[SOCKET_BUFFER_SIZE] = {'\0'};
    unsigned char buffer_out[SOCKET_BUFFER_SIZE] = {'\0'};
    //int server_fd = 1;
    int len, ret;
    off_t offset;
    
    zmq::context_t context(1);
    zmq::socket_t socket(context,ZMQ_REQ);
    int64_t more;
    size_t more_size = sizeof(more);
    try
    {   
        /*
         * 1. Connect to the server
         * 
         * */

        //printf("   2.1. Connecting to the server %d... ",serverID);
        socket.connect(this->SERVER_ADDRESS[serverID].c_str());

        //printf("connected!\n");
        /*
         * 2. Send the request block data COMMAND first to the server so that the server can know what the client intends to do
         * */
         
        cmd = CMD_REQUEST_BLOCK_DATA;
        memset(buffer_out,0,SOCKET_BUFFER_SIZE);
        memcpy(buffer_out,&cmd,sizeof(cmd));

        socket.send(buffer_out,SOCKET_BUFFER_SIZE);
        //printf("   2.2. Sending request block data...");
        //wait for the server to accept the command request
        socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
        //printf("OK\n");
        auto start = time_now;
        /*
         * 3. The client sends the indexrequest token to the server to receive the corresponding block data
         * */
        memset(buffer_out,0,SOCKET_BUFFER_SIZE);
        memcpy(buffer_out,&index_request,sizeof(index_request));
        //printf("   2.3. Sending RequestIndex token..."); 
        socket.send(buffer_out,SOCKET_BUFFER_SIZE);
        
        //printf("OK\n");
        
        /*
         * 5. Receive the block data sent back by the server 
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
        // transfer serialized_data into search & update data;
        offset = 0;
  
        for(int i = 0 ; i < NUM_IDX_PER_DIM ; i++)
        {
            memcpy(search_data[i],&serialized_data[offset],MATRIX_COL_SIZE);
            offset += MATRIX_COL_SIZE;
            memcpy(update_data[i],&serialized_data[offset],MATRIX_ROW_SIZE/BYTE_SIZE);
            offset+= MATRIX_ROW_SIZE/BYTE_SIZE;
        }
        auto end  = time_now;
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end-start);
        double time = elapsed.count()/1000.0;
        printf("Time to download data from a server %8.4f ms \n",time);
    
    }
    catch(exception &ex)
    {
        ret = CLIENT_REQUEST_BLOCK_DATA_ERR;
        goto exit;
    }
    ret = 0;
    
exit:

    //clear everything to free the memory
    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
    memset(buffer_out,0,SOCKET_BUFFER_SIZE);
    socket.disconnect(this->SERVER_ADDRESS[serverID].c_str());
    socket.close();
    return ret;
}
#endif
#if defined (CLIENT_SERVER_MODE)
int Client_DSSE::sendBlock_data(IndexRequest index_request, int serverID, MatrixType** search_data, MatrixType **update_data)
 {
    int cmd;
    Miscellaneous misc;
    unsigned char buffer_in[SOCKET_BUFFER_SIZE] = {'\0'};
    unsigned char buffer_out[SOCKET_BUFFER_SIZE] = {'\0'};
    //int server_fd = 1;
    int ret;
    string filename_temp_with_path;
    int n; 
    FILE* finput = NULL;	
    off_t filesize, offset;
    size_t size_sent;
    
    zmq::context_t context(1);
    zmq::socket_t socket(context,ZMQ_REQ);
    
    try
    {
        /*
         * 1. Connect to the server
         * 
         * */
        //printf("   2.1. Connecting to the server %d... ",serverID);
        socket.connect(this->SERVER_ADDRESS[serverID].c_str());
        //printf("connected!\n");
        /*
         * 2. Send the request block data COMMAND first to the server so that the server can know what the client intends to do
         * */
        cmd = CMD_UPDATE_BLOCK_DATA;
        memset(buffer_out,0,SOCKET_BUFFER_SIZE);
        memcpy(buffer_out,&cmd,sizeof(cmd));
        socket.send(buffer_out,SOCKET_BUFFER_SIZE);
        //printf("   2.2. Sending update block data...");
        //wait for the server to accept the command request
        socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
        //printf("OK\n");
        auto start = time_now;
        /*
         * 3. The client sends the indexrequest token to the server to receive the corresponding block data
         * */
        memset(buffer_out,0,SOCKET_BUFFER_SIZE);
        memcpy(buffer_out,&index_request,sizeof(index_request));
        //printf("   2.3. Sending RequestIndex token..."); 
        socket.send(buffer_out,SOCKET_BUFFER_SIZE);
        //wait for ack
        socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
        
        //printf("OK\n");
        
        /* Local processing: serialize the search & update data */
        offset = 0;
        memset(this->serialized_data,0,this->serialized_data_len);
        for(int i = 0 ; i < NUM_IDX_PER_DIM ; i ++)
        {
            memcpy(&this->serialized_data[offset],search_data[i],MATRIX_COL_SIZE);
            offset+= MATRIX_COL_SIZE;
            memcpy(&this->serialized_data[offset],update_data[i],MATRIX_ROW_SIZE/BYTE_SIZE);
            offset+= MATRIX_ROW_SIZE/ BYTE_SIZE;
        }
        /*
         * 2. Send block data to the server 
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
        auto end  = time_now;
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end-start);
        double time = elapsed.count()/1000.0;
        printf("Time to upload data to a server: %8.4f ms \n",time);
    
    }
    catch (exception &ex)
    {
        ret = CLIENT_UPDATE_BLOCK_DATA_ERR;
        goto exit;
    }
    /*
    * 7. End the sessions, close the connection
    * 
    * */
    ret = 0;
    
exit:

    socket.disconnect(this->SERVER_ADDRESS[serverID].c_str());
    socket.close();
    memset(buffer_in,0,sizeof(buffer_in));
    memset(buffer_out,0,sizeof(buffer_out));
    filename_temp_with_path.clear();
    return ret;
}

void* Client_DSSE::thread_precomputed_key_func(void* param)
{
    auto start = time_now;
    
    DSSE* dsse = new DSSE();
    ThreadPrecomputedKey* opt = (ThreadPrecomputedKey*) param;
    if(opt->genKey_decrypt == true)
    {
        if(opt->op == SEARCH_OPERATION)
        {
            dsse->precomputeAES_CTR_keys_decrypt(opt->row_idx,opt->serverID,opt->op,opt->col_counter_arr,opt->precomputed_key,opt->pKey);
        }
        else
            dsse->precomputeAES_CTR_keys_decrypt(opt->col_idx,opt->serverID,opt->op,opt->col_counter_arr,opt->precomputed_key,opt->pKey);
    }
    else
    {
        dsse->precomputeAES_CTR_keys_reencrypt(opt->col_idx,opt->row_idx,opt->serverID,opt->op,opt->col_counter_arr,opt->row_counter_arr,opt->precomputed_key,opt->pKey);
    }
     
    auto end  = time_now;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end-start);
    double time = elapsed.count()/1000.0;
    printf("Time to key precomputation: %8.4f ms \n",time);
    delete dsse;
    pthread_exit(NULL);
    //return 0;
}
void* Client_DSSE::thread_requestBlock_data(void* param)
{
    ThreadDataTransmit* data_request = (ThreadDataTransmit*) param;
    Client_DSSE* call = new Client_DSSE();
    call->requestBlock_data(data_request->idx_request,data_request->serverID,data_request->search_data,data_request->update_data);
    
    delete call;
    pthread_exit(NULL);
}
void* Client_DSSE::thread_uploadBlock_data(void* param)
{
    auto start = time_now;
    ThreadDataTransmit* data_upload = (ThreadDataTransmit*) param;
    Client_DSSE* call = new Client_DSSE();
    call->sendBlock_data(data_upload->idx_request,data_upload->serverID,data_upload->search_data,data_upload->update_data);
    
    auto end  = time_now;
    cout<<"Time to upload data from a thread: "<<std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count()/1000000.0<<endl;
    delete call;
    pthread_exit(NULL);
}
#endif

void *Client_DSSE::thread_getKey_info_func(void* param)
{
        auto start = time_now;
    ThreadGetKeyInfo* opt = (ThreadGetKeyInfo*) param;
    DSSE* dsse = new DSSE();

    dsse->getKey_from_block(opt->decrypted_data,opt->op,opt->serverID,opt->lstKey,opt->set_free_idx);

    delete dsse;
    pthread_exit((void*)opt);
        auto end = time_now;
    cout<<"Time to get key info from a thread: "<<std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count()/1000000.0<<endl;
}
void *Client_DSSE::thread_createNew_data_representation_func(void* param)
{
    ThreadCreateNewDataRepresentation *opt = (ThreadCreateNewDataRepresentation*) param;
    DSSE* dsse = new DSSE();    
    dsse->genBlock_from_key(opt->lstKey,opt->serverID,opt->op,opt->data);
    delete dsse;
    pthread_exit(NULL);
    return 0;
}