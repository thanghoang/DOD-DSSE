#ifndef CLIENT_DSSE_H
#define CLIENT_DSSE_H

#include <MasterKey.h>
#include <DSSE_Param.h>
#include <struct_MatrixType.h>

#include <struct_OperationToken.h>
#include <DSSE_Hashmap_Key_Class.h>

#include "struct_IndexRequest.h"
#include "struct_threadPrecomputedKey.h"
#include "struct_threadDataTransmit.h"
#include "struct_threadGetKeyInfo.h"
#include "struct_threadCreateNewDataRepresentation.h"
//thread
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

class Client_DSSE
{
private:
    MasterKey* masterKey;
    
    // Global & static file counter
    bool data_structure_constructed;
	static TYPE_COUNTER gc;

    // Security parameter/Extractor Salt (Deterministic Seed) for generating Krawczyk PRK using RDRAND
	unsigned char extractor_salt[BLOCK_CIPHER_SIZE];
	// Security parameter/Pseudo Random Key (uniform & random intermediate key) for generating Krawczyk KDF (BLOCK_CIPHER_SIZE bytes)
	unsigned char pseudo_random_key[BLOCK_CIPHER_SIZE];
    
 
    MatrixType** I[NUM_SERVERS];
    
    vector<TYPE_INDEX> setKeywordIdx[NUM_SERVERS];
    vector<TYPE_INDEX> setFileIdx[NUM_SERVERS];
    TYPE_COUNTER* row_counter_arr[NUM_SERVERS];
    TYPE_COUNTER* column_counter_arr[NUM_SERVERS];
    
    string SERVER_ADDRESS[NUM_SERVERS];

    int bit_field_reset(MatrixType *I, TYPE_INDEX col, int bit_position);
    
#if defined (CLIENT_SERVER_MODE)
    MatrixType serialized_data[NUM_IDX_PER_DIM* MATRIX_COL_SIZE + NUM_IDX_PER_DIM*MATRIX_ROW_SIZE/BYTE_SIZE];
    TYPE_INDEX serialized_data_len;
#endif
public:
	
    Client_DSSE();
    ~Client_DSSE();
    
    int genMaster_key();
    int createEncrypted_data_structure();
    int searchKeyword(string keyword, TYPE_COUNTER &number);
    int addFile(string filename, string path);
    int delFile(string filename, string path);
    
    
    int operation(int op, string strInput);      

    IndexRequest idx_request[NUM_SERVERS];


#if defined(CLIENT_SERVER_MODE)
    int sendFile(string filename, string path, int SENDING_TYPE, int serverID);
int sendBlock_data(IndexRequest index_request, int serverID, 
                            MatrixType** search_data, MatrixType **update_data);
    int requestBlock_data(  IndexRequest index_request, int serverID, 
                            MatrixType** search_data, MatrixType** update_data);
#endif
    
    //store all extracted keywords
    static TYPE_KEYWORD_DICTIONARY keywords_dictionary;


public :
// Hash map where the trapdoors for the keywords are stored
static	TYPE_GOOGLE_DENSE_HASH_MAP T_W;

	// Static hash map where the trapdoors for the files are stored
static	TYPE_GOOGLE_DENSE_HASH_MAP T_F;

static TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX T_W_IDX[NUM_SERVERS];
static    TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX T_F_IDX[NUM_SERVERS];
   
static unsigned char precomputed_row_key[NUM_SERVERS][MATRIX_ROW_SIZE*BLOCK_CIPHER_SIZE];

static vector<TYPE_INDEX> lstT_W_IDX[NUM_SERVERS];
static vector<TYPE_INDEX> lstT_F_IDX[NUM_SERVERS];

static vector<vector<TYPE_INDEX>> kw_file_pair[NUM_SERVERS];



/* THREAD IMPLEMENTATION */

private:
    
    /* 
     * Thread variables
     * */
#if defined(CLIENT_SERVER_MODE)
    pthread_t thread_requestData[NUM_SERVERS];
    pthread_t thread_uploadData[NUM_SERVERS];

    ThreadDataTransmit* data_transmit[NUM_SERVERS];
#endif
    /* crypto key precomputation */
    TYPE_INDEX update_idx_arr[NUM_SERVERS][NUM_IDX_PER_DIM];
    TYPE_INDEX search_idx_arr[NUM_SERVERS][NUM_IDX_PER_DIM]; 
    ThreadPrecomputedKey* key_decrypt_search_param[NUM_SERVERS];
    ThreadPrecomputedKey* key_reencrypt_search_param[NUM_SERVERS];
    
    pthread_t thread_key_decrypt_search[NUM_SERVERS];
    pthread_t thread_key_reencrypt_search[NUM_SERVERS];

    ThreadPrecomputedKey* key_decrypt_update_param[NUM_SERVERS];
    ThreadPrecomputedKey* key_reencrypt_update_param[NUM_SERVERS];
    
    pthread_t thread_key_decrypt_update[NUM_SERVERS];
    pthread_t thread_key_reencrypt_update[NUM_SERVERS];
    
    
    /* get key info */
    
    pthread_t thread_key_info_update[NUM_SERVERS];
    pthread_t thread_key_info_search[NUM_SERVERS];
    
    ThreadGetKeyInfo* key_info_update_param[NUM_SERVERS];
    ThreadGetKeyInfo* key_info_search_param[NUM_SERVERS];
    
    /* create new data representation */
    
    pthread_t thread_new_data_representation_update[NUM_SERVERS];
    pthread_t thread_new_data_representation_search[NUM_SERVERS];
    
    ThreadCreateNewDataRepresentation* new_data_representation_update_param[NUM_SERVERS];
    ThreadCreateNewDataRepresentation* new_data_representation_search_param[NUM_SERVERS];
    
    
#if defined(CLIENT_SERVER_MODE)
    static void* thread_requestBlock_data(void* param);
    static void* thread_uploadBlock_data(void* param);
#endif

    static void* thread_getKey_info_func(void* param);
    static void* thread_precomputed_key_func( void* precomputed_key);
    static void* thread_createNew_data_representation_func(void* param);

};
#endif // CLIENT_DSSE_H
