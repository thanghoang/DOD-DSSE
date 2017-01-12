#ifndef DSSE_PARAM_H
#define DSSE_PARAM_H

#include "DSSE_Hashmap_Key_Class.h"																			   // For using Hashmap_Key_Class as the type for google dense hash map


#define ZERO_VALUE 0										                                                           // Defines value 0
#define ONE_VALUE 1											                                                           // Defines value 1
#define SEED_SIZE 4											                                                           // Defines the size of the seed/entropy needed for random numbers generators
#define INTEGER_SIZE_IN_BYTES 4								                                                           // Defines the size of an integer type in bytes
#define LONG_SIZE_IN_BYTES 8								                                                           // Defines the size of a long type in bytes
#define BYTE_SIZE 8											                                                           // Defines the size of a byte type in bits
#define RDRAND_RETRY_NUM 10																							   // Defines the number of retries for RDRAND function
#define TRAPDOOR_SIZE 16 //10??Collision many!!!																							   // Defines the size of the trapdoors (80-bits)
#define TRAPDOOR_PLUS_ONE 11																						   // Defines the size of hmac or cmac or omac (80-bits) output with null termination
#define NONCE_SIZE 12																								   // Defines the size of nonce used for file encryption (CCM mode)
#define BLOCK_CIPHER_SIZE 16																						   // Defines the size of block cipher
#define KEY_SIZE 16 																								   // Defines the size of the key
#define HASH_SIZE 32																								   // Defines the size of output of hmac_sha256 (the hash size)
#define MAX_NAME_SIZE 100																							   // Defines the maximum size of a name or a keyword (file name, keyword, etc.)
#define MAX_FNAME_SIZE 100																							   // Defines the maximum size of a file name

#define MAX_NUM_KEYWORDS 250000																					   // Defines the maximum number of keywords for the scheme

#define MAX_NUM_OF_FILES 250000																	   // Defines the maximum number of files for the scheme
#define MATRIX_ROW_SIZE MAX_NUM_KEYWORDS*2					                                                           // Defines the row size of matrix I (nxm)
static const string gcsMatrixPiece = "/scratch/simulation_thanghoang/ACSAC/250000F/ACSAC_data/";
static const string gcsDataStructureFilepath = "/scratch/simulation_thanghoang/ACSAC/250000F/ACSAC_data/";


//define the ratio between the maximum file that can be added and the maximum number of file allowed
#define FILE_LOADING_FACTOR 0.5
//define the ratio between the maximum keyword that can be added and the maximum number of keyword allowed
#define KEYWORD_LOADING_FACTOR 0.5


#define IF_NUM_OF_FILES_IS_EVEN (MAX_NUM_OF_FILES%BYTE_SIZE)		                                                   // Defines if the number of files is even or odd (0 if even,1 if odd)

#define MATRIX_COL_SIZE ((MAX_NUM_OF_FILES*2/BYTE_SIZE))		                                                           // Defines the 
#define NUM_BLOCKS ((MATRIX_COL_SIZE/BLOCK_CIPHER_SIZE))																   


#define MAC_NAME "MAC"																							   	   // Defines the name of MAC file used during encrypting files


#define CLIENT_SERVER_MODE 
//#define ENCRYPT_PHYSICAL_FILE
//#define SEND_SEARCH_FILE_INDEX
#define LOAD_PREVIOUS_DATA_MODE
#define UPLOAD_DATA_STRUCTURE_MANUALLY_MODE

//Client- Service Define
//#define PEER_ADDRESS_0 "tcp://192.168.123.141:4433"
//#define PEER_ADDRESS_1 "tcp://192.168.123.142:4433"

#define PEER_ADDRESS "tcp://*:4433"
#define PEER_ADDRESS_0 "tcp://128.193.38.87:4433"
#define PEER_ADDRESS_1 "tcp://128.193.38.19:4432"

#define NUM_SERVERS 2

//Commands for Client- Server Interation

#define CMD_SEND_DATA_STRUCTURE         0x000010
#define CMD_ADD_FILE_PHYSICAL           0x00000F
#define CMD_DELETE_FILE_PHYSICAL        0x000040

#define CMD_SEARCH_OPERATION            0x000020



#define CMD_REQUEST_BLOCK_DATA          0x000050

#define CMD_UPDATE_BLOCK_DATA           0x000060
#define CMD_SUCCESS                     "CMD_OK"

#define REQUEST_TIMEOUT                 -76


//define the default filename of some data structures in DSSE scheme
#define FILENAME_MATRIX                 "data_structure"
#define FILENAME_GLOBAL_COUNTER         "global_counter"
#define FILENAME_BLOCK_STATE_MATRIX     "block_state_mat"
#define FILENAME_BLOCK_STATE_ARRAY     "block_state_arr"
#define FILENAME_BLOCK_COUNTER_ARRAY     "block_counter_arr"
#define FILENAME_I_PRIME                "i_prime"
#define FILENAME_SEARCH_RESULT          "search_result"


/* ACSAC */
#define FILENAME_SEARCH_DATA "search_data"
#define FILENAME_UPDATE_DATA "update_data"
/* end ACSAC */
//buffer size of each packet for sending / receiving 
#define SOCKET_BUFFER_SIZE            32

//MACROS
												   // Toggles a bit by its position within the character byte
#define BIT_READ(character, position, the_bit)	((*the_bit = *character & (1 << position)))							   // Reads the "position"-th bit within the character byte
#define BIT_SET(character, position) ((*character |= 1 << position))													   // Sets a bit by its position within the character byte
#define BIT_CLEAR(character, position) ((*character &= ~(1 << position)))											   // Clears a bit by its position within the character byte
#define BIT_TOGGLE(character, position)	((*character ^= 1 << position))												   // Toggles a bit by its position within the character byte
#define BIT_CHECK(var,pos) !!((*var) & (1<<(pos)))

#include <stdlib.h>
#include <stdio.h>																									   // For FILE, fwrite, fread
#include <string.h>																									   // For string related operations
#include <cerrno>																									   // For C++ version of the Standard C Library header errno.h
#include <algorithm>																								   // For std::copy utility
#include <functional>																								   // For mem_fun utility
#include <iostream>																									   // For standard I/O stream
#include <fstream>																									   // For file stream
#include <sstream>																									   // For string stream
#include <bitset>																									   // For bitwise operations
#include <vector>																									   // For Vector operations
#include <iterator>																									   // For iterator operations
#include <dirent.h>																									   // For operations in a directory
#include <sys/types.h>																								   // For basic data types
#include <sys/stat.h>																								   // For using stat() function
#include <unistd.h>																									   // For standard symbolic constants and types
#include <set>																							   			   // For using Set data structure
#include <sparsehash/dense_hash_map>																				   // For hash map and its implementation
#include <boost/algorithm/string/split.hpp>																		   	   // For using Boost library's string split operations
#include <boost/algorithm/string.hpp>																				   // For using Boost library's string operations like trim(), etc.
#include "jg_timing.h"																								   // For CPU time computations and benchmarking results
#include "climits"

#include <chrono>


using namespace std;																								   // Standard namespace
using google::dense_hash_map;		 						                                                           // Namespace where hash table related class lives by default
using tr1::hash;					 						                                                           // For hash function used in hash table (tr1::hash or __gnu_cxx::hash), depending on your OS
using namespace boost::algorithm;

																								// Global & static variable for detecting errors
static const string gcsFilepath = "/scratch/simulation_thanghoang/small_test_set/";			// Absolute path of files directory
static const string gcsEncFilepath = "/home/daniellin/Desktop/encr_file/";				// Absolute path of encrypted files directory
static const string gcsUpdateFilepath = "/home/daniellin/Desktop/up_file/";			// Absolute path of files directory
static const string gcsEncryptedUpdateFilepath = "/home/daniellin/Desktop/encr_up_file/";
static const string gcsKwHashTable = "kw_hashtable";
static const string gcsFileHashTable = "file_hashtable";
static const string gcsListFreeFileIdx = "lstFreeFileIdx";
static const string gcsListFreeKwIdx = "lstFreeKwIdx";
static const string gcsListNonFreeFileIdx = "lstNonFreeFileIdx";
static const string gcsListNonFreeKwIdx = "lstNonFreeKwIdx";

const char* const delimiter = "`-=[]\\;\',./~!@#$%^&*()+{}|:\"<>? \n\t\v\b\r\f\a";	// Delimiter separating words while extracting them from files															// Delimiter while extracting keywords from a file
typedef unsigned long int TYPE_COUNTER;
typedef unsigned long int TYPE_INDEX;
typedef unsigned char TYPE_WORD;


// A Structure with a unsigned character array pointer and its size stored in it
struct UCharArray{
	unsigned char *pUChar_array;
	int uChar_array_size;

};

#define time_now std::chrono::high_resolution_clock::now()
#define MATRIX_PIECE_COL_SIZE (MATRIX_COL_SIZE/50)

/* ACSAC */
class TokenInfo;
#define NUM_IDX_PER_DIM 2
#define ROW_DATA 0
#define COL_DATA 1

#define SEARCH_OPERATION ROW_DATA
#define UPDATE_OPERATION COL_DATA

#define OP_ADD_FILE 3
#define OP_DELETE_FILE 4

#define FIRST_BIT_ONE 0x80
#define BIT_POS 7
/* 
 * HASH TABLE DATA STRUCTURE
 */
typedef dense_hash_map<hashmap_key_class,TokenInfo*,hashmap_key_class,hashmap_key_class> TYPE_GOOGLE_DENSE_HASH_MAP;
typedef dense_hash_map<TYPE_INDEX,hashmap_key_class> TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX;

typedef set<string> TYPE_KEYWORD_DICTIONARY;


#endif
