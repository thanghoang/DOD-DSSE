#ifndef DSSE_H
#define DSSE_H

#include "struct_MatrixType.h"
#include "struct_SearchToken.h"
#include "CTokenInfo.h"
#include "Client_DSSE.h"
#include "tomcrypt_cpp.h"
#include "tomcrypt.h"

#define KEYWORD_TOKEN_GENERATION_ERR            -0x00000001
#define DATA_STRUCTURE_NOT_BUILT_ERR            -0x00000002
#define MAX_KEYWORD_INDEX_EXCEEDED_ERR          -0x00000003
#define MAX_FILE_INDEX_EXCEEDED_ERR             -0x00000004
#define MAX_NUM_BLOCK_EXCEEDED_ERR              -0x00000005
#define FILE_OPEN_ERR                           -0x00000006
#define KEY_NULL_ERR                            -0x00000007


#define KEY_GENERATION_ERR                      -0x00000008
#define SETUP_DATA_STRUCTURE_ERR                -0x00000009
#define ENCRYPT_DATA_STRUCTURE_ERR              -0x0000000A
#define INITIALIZE_MATRIX_ERR                   -0x0000000B
#define SEARCH_ERR                              -0x0000000C
#define ADD_TOKEN_ERR                           -0x0000000D
#define DELETE_TOKEN_ERR                        -0x0000000E
#define ADD_ERR                                 -0x0000000F
#define DELETE_ERR                              -0x00000010
#define REQUEST_BLOCK_IDX_ERR                   -0x00000011
#define FETCH_BLOCK_DATA_ERR                    -0x00000012
#define BIT_FIELD_ACCESS_ERR                    -0x00000013


#define SEARCH_TOKEN_ROW_IDX_ERR                -0x00000101

#define INVALID_BIT_NUMBER_ERR                  -0x00000200         //DSSE::bit_field_acces


#define CLIENT_SEND_FILE_ERR                    -0x00000300
#define CLIENT_CREATE_DATA_STRUCTURE_ERR        -0x00000301
#define CLIENT_SEARCH_ERR                       -0x00000302
#define CLIENT_REQUEST_BLOCK_DATA_ERR           -0x00000303
#define CLIENT_UPDATE_BLOCK_DATA_ERR            -0x00000304
#define CLIENT_ADD_FILE_ERR                     -0x00000305
#define CLIENT_DELETE_FILE_ERR                  -0x00000306
         


#define HASH_TABLE_NULL_ERR                     -0x00000100
#define COUNTER_EXCEED_LIMIT                    -0x00000101


/* ACSAC */

#include "struct_OperationToken.h"
#include "struct_threadPrecomputedKey.h"
class DSSE{
private:

    
    //bit_field_access original lies in DynamicSSE_Matrix
    int bit_field_access(MatrixType **I, TYPE_INDEX row, TYPE_INDEX col, int bit_position);
    
    //bit_field_resest : opposite to the bit_file_access
    int bit_field_reset(MatrixType **I, TYPE_INDEX row, TYPE_INDEX col, int bit_position);

public:
    DSSE();
    ~DSSE();
    
    int createKW_file_pair( 
                            TYPE_GOOGLE_DENSE_HASH_MAP &rT_W, 
                            TYPE_GOOGLE_DENSE_HASH_MAP &rT_F,
                            TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX rT_W_IDX[],
                            TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX rT_F_IDX[],
                            vector<TYPE_INDEX> setKeywordIdx[],
                            vector<TYPE_INDEX> setFileIdx[],
                            string path, 
                            MasterKey *pKey);
    int encryptData_structure(  MatrixType **I, int serverID,
                                TYPE_COUNTER *pKeywordCounterArray,
                                TYPE_COUNTER *pBlockCounterArray,
                                MasterKey *pKey);
                                
    int setupData_structure(    MatrixType **I[], 
                            TYPE_GOOGLE_DENSE_HASH_MAP &rT_W, 
                            TYPE_GOOGLE_DENSE_HASH_MAP &rT_F, 
                            TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX rT_W_IDX[NUM_SERVERS],
                            TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX rT_F_IDX[NUM_SERVERS],
                            vector<TYPE_INDEX> setKeywordIdx[],
                            vector<TYPE_INDEX> setFileIdx[],
                            TYPE_COUNTER* pRowCounterArray[NUM_SERVERS],
                            TYPE_COUNTER* pColumnCounterArray[NUM_SERVERS],
                            vector<string> &rFileNames, 
                            string path, 
                            string encrypted_files_path, 
                            MasterKey *pKey,
                            TYPE_KEYWORD_DICTIONARY &keyword_dictionary);
    
    
    int updateT(    OperationToken operation_token,
                    vector<TYPE_INDEX> setIdx[NUM_SERVERS], 
                    TYPE_COUNTER* counter_arr[NUM_SERVERS], 
                    TYPE_GOOGLE_DENSE_HASH_MAP &rT,
                    TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX rT_IDX[NUM_SERVERS],
                        vector<TYPE_INDEX> lstT_IDX[NUM_SERVERS]                //not important param, delete later!
                    );

    int getRandomElement(TYPE_INDEX &randomIdx,vector<TYPE_INDEX> &setIdx);
    
    int genRandomNumber(TYPE_INDEX &output, TYPE_INDEX size);
    
    int genToken(OPERATION_TOKEN &operation_token, int op,
		string strInput,
        vector<TYPE_INDEX> setDummy_idx[NUM_SERVERS],
        TYPE_GOOGLE_DENSE_HASH_MAP &rT, 
        MasterKey *pKey);
    
    int setBlock(TYPE_INDEX block_index,    //input
                        int op,              //input
                        MatrixType** I,             //input & output
                        MatrixType* I_prime);       //input
    int getBlock(   TYPE_INDEX block_index,    //input
                        int op,              //input
                        MatrixType** I,             //input
                        MatrixType* I_prime);       //output
                        
                        
    int encBlock(  MatrixType *I,  //input
                        int op,
                        int serverID,
                        TYPE_INDEX idx,
                        TYPE_COUNTER counter,   
                        TYPE_COUNTER counter_arr[],
                        MatrixType *I_prime, //output
                        MasterKey *pKey
                        );
     int decBlock(  MatrixType *I,  //input
                        int op,
                        int serverID,
                        TYPE_INDEX idx,
                        TYPE_COUNTER counter,   
                        TYPE_COUNTER counter_arr[],
                        MatrixType *I_prime, //output
                        TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX &rT_IDX, //this is used to decrypt only valid address ->accelerate the speed into twice!
                        MasterKey *pKey
                        );
    int getKey_from_block(MatrixType* I, int op, int serverID,
                                vector<hashmap_key_class> &lstKey, 
                                vector<TYPE_INDEX> setDummy_idx);
    
    int genUpdate_lstKey_from_file(string filename_with_path, int op, 
                                    vector<hashmap_key_class> &lstKey, //output
                                    TYPE_GOOGLE_DENSE_HASH_MAP &rT_W,
                                    vector<TYPE_INDEX> setDummyIdx[NUM_SERVERS],
                                    MasterKey* pKey
                                    );
    
    int genBlock_from_key(vector<hashmap_key_class> input, int serverID,  int op,
                                    MatrixType *output);
    int updateBlock(MatrixType* I,              //update 1 2 bits from the decrypted data
                    TYPE_INDEX empty_idx,
                    TYPE_INDEX old_idx_of_new_data);

    int bit_field_access(MatrixType *I,
                        TYPE_INDEX col,
                        int bit_position);
    int bit_field_reset(MatrixType *I,
		TYPE_INDEX col,
		int bit_position);
    int enc_decBlock_with_preAESKey(MatrixType *I,  int op, //input 
                        unsigned char preKey[],
                        MatrixType *I_prime);
                        
   // offline phase 
    int precomputeAES_CTR_keys(TYPE_INDEX* col_idx_arr, TYPE_INDEX* row_idx_arr, int serverID,
                                TYPE_COUNTER* col_counter_arr, TYPE_COUNTER* row_counter_arr, 
                                unsigned char* key_search_decrypt, unsigned char* key_update_decrypt, 
                                unsigned char* key_search_reencrypt[NUM_IDX_PER_DIM], unsigned char* key_update_reencrypt[NUM_IDX_PER_DIM],
                                MasterKey *pKey);
                                
    int precomputeAES_CTR_keys_decrypt(TYPE_INDEX* idx_arr, int serverID, int op,
                                TYPE_COUNTER* col_counter_arr, 
                                unsigned char* key_decrypt,
                                MasterKey* pKey);           

    int precomputeAES_CTR_keys_reencrypt(TYPE_INDEX* col_idx_arr, TYPE_INDEX* row_idx_arr, int serverID, int op,
                                TYPE_COUNTER* col_counter_arr, TYPE_COUNTER* row_counter_arr,  
                                unsigned char* key_reencrypt,
                                MasterKey* pKey);
                                
                                
    int updateRow_key(  TYPE_COUNTER* row_counter_arr, int serverID, TYPE_INDEX updateIdx,
                        unsigned char output[MATRIX_ROW_SIZE*BLOCK_CIPHER_SIZE],
                        MasterKey *pKey);
    int precomputeRow_keys( TYPE_COUNTER* row_counter_arr[NUM_SERVERS],
                            unsigned char output[NUM_SERVERS][MATRIX_ROW_SIZE*BLOCK_CIPHER_SIZE],
                            MasterKey *pKey);
                            
// func supporting to build matrix from smaller pieces
    int loadWhole_encrypted_matrix_from_file(MatrixType** I, int serverID);
    int createEncryptedMatrix_from_kw_file_pair(TYPE_COUNTER* col_counter_arr[NUM_SERVERS]);
    int scanDatabase(
		vector<string> &rFileNames,
		TYPE_KEYWORD_DICTIONARY &rKeywordsDictionary,
        string path);
public:
    static double time;
    
    
    
    int _rdrand64_asm(unsigned long int *therand);
    int invokeFortuna_prng(unsigned char *seed, unsigned char *key, int seedlen, int keylen);
    int rdrand(unsigned char* output, unsigned int output_len, unsigned int retry_limit);
};


#endif
