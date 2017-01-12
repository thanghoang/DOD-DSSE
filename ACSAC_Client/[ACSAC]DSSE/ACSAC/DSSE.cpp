
#include "MasterKey.h"              //for data structure of master key
#include "tomcrypt_cpp.h"           // for traditional crypto primitives
#include "DSSE.h"
#include "Keyword_Extraction.h"     //extract keywords from file
#include "Miscellaneous.h" 
#include "DSSE_Trapdoor.h"
#include "DSSE_FileCrypt.h"              // for file encryption / decryption 

#include "DSSE_KeyGen.h"
#include "climits"

DSSE::DSSE()
{
    
}

DSSE::~DSSE()
{
    
}
double DSSE::time = 0; 
/**
 * Provides the bit field access to each entry of the matrix I for a given row & column
 *
 * @param I					The searchable representation,i.e., the matrix data structure with its rows corresponding to keywors and columns corresponding to files
 * @param row				The row of I that has to be accessed
 * @param col				The column of I that has to be accessed
 * @param bit_position		The bit position of an entry of I that needs to be set
 * @return 0 if successful
 * Anvesh Ragi			10-02-2013		Function created
 */
int DSSE::bit_field_access(MatrixType **I,
		TYPE_INDEX row,
		TYPE_INDEX col,
		int bit_position)
{
    int ret;
    try
    {
        switch(bit_position)
        {
        case 0: I[row][col].bit_data.bit1 = 1;
        break;

        case 1: I[row][col].bit_data.bit2 = 1;
        break;

        case 2: I[row][col].bit_data.bit3 = 1;
        break;

        case 3: I[row][col].bit_data.bit4 = 1;
        break;

        case 4: I[row][col].bit_data.bit5 = 1;
        break;

        case 5: I[row][col].bit_data.bit6 = 1;
        break;

        case 6: I[row][col].bit_data.bit7 = 1;
        break;

        case 7: I[row][col].bit_data.bit8 = 1;
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
int DSSE::bit_field_reset(MatrixType **I,
		TYPE_INDEX row,
		TYPE_INDEX col,
		int bit_position)
{
    int ret;
	try
    {
        switch(bit_position){

        case 0: I[row][col].bit_data.bit1 = 0;
        break;

        case 1: I[row][col].bit_data.bit2 = 0;
        break;

        case 2: I[row][col].bit_data.bit3 = 0;
        break;

        case 3: I[row][col].bit_data.bit4 = 0;
        break;

        case 4: I[row][col].bit_data.bit5 = 0;
        break;

        case 5: I[row][col].bit_data.bit6 = 0;
        break;

        case 6: I[row][col].bit_data.bit7 = 0;
        break;

        case 7: I[row][col].bit_data.bit8 = 0;
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

int DSSE::setupData_structure(MatrixType **I[],
		TYPE_GOOGLE_DENSE_HASH_MAP &rT_W,
		TYPE_GOOGLE_DENSE_HASH_MAP &rT_F,
        TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX rT_W_IDX[NUM_SERVERS],
        TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX rT_F_IDX[NUM_SERVERS],
        vector<TYPE_INDEX> setKeywordIdx[NUM_SERVERS],
        vector<TYPE_INDEX> setFileIdx[NUM_SERVERS],
        TYPE_COUNTER* pRowCounterArray[NUM_SERVERS],
        TYPE_COUNTER* pColumnCounterArray[NUM_SERVERS],
		vector<string> &rFileNames,
		string path,
		string encrypted_files_path,
		MasterKey *pKey,
        TYPE_KEYWORD_DICTIONARY &keywords_dictionary)
{
	TYPE_INDEX row = 0, col = 0;
	auto start = time_now, end = time_now, elapsed = time_now;
    set<string>::iterator iter;
    int ret;
    
    // Variable for empty keyword
    TYPE_WORD empty_label[6] = "EMPTY";
    // Variable for delete keyword
    TYPE_WORD delete_label[7] = "DELETE";
    hashmap_key_class empty_key = hashmap_key_class(empty_label,6);
    hashmap_key_class delete_key = hashmap_key_class(delete_label,7);
    DSSE_Trapdoor* tfunc = new DSSE_Trapdoor();
    
    TYPE_INDEX max_row_idx =0;
    TYPE_INDEX max_col_idx = 0;
    
#if defined (ENCRYPT_PHYSICAL_FILE)
    string str_clear_folder_cmd = "exec rm -r "+ encrypted_files_path +"*";
    FileCrypt* fc = new FileCrypt();
 
#endif
	// NULL checks    
    if(pKey->isNULL())
    {
        ret = KEY_NULL_ERR;
        goto exit;
    }
	
	try
    {
        /*
         * 0. Initialization
         */
		// ******** SHOULD SET THE SIZES OF HASHMAPS WHICH IS REQUIRED ENOUGH ACCORDING TO DEFAULT LOAD FACOR ********
		rT_W = TYPE_GOOGLE_DENSE_HASH_MAP(MAX_NUM_KEYWORDS*KEYWORD_LOADING_FACTOR);
        rT_W.resize(MAX_NUM_KEYWORDS);
		rT_W.max_load_factor(KEYWORD_LOADING_FACTOR);
		rT_W.min_load_factor(0.0);
        rT_W.set_empty_key(empty_key);
		rT_W.set_deleted_key(delete_key);
	     
		rT_F = TYPE_GOOGLE_DENSE_HASH_MAP(MAX_NUM_OF_FILES*FILE_LOADING_FACTOR);
        rT_F.resize(MAX_NUM_OF_FILES);
        rT_F.max_load_factor(FILE_LOADING_FACTOR);
		rT_F.min_load_factor(0.0);
		rT_F.set_empty_key(empty_key);
		rT_F.set_deleted_key(delete_key);
        
        
        for(int k = 0 ; k < NUM_SERVERS;k++)
        {
            rT_W_IDX[k] = TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX(MAX_NUM_KEYWORDS*KEYWORD_LOADING_FACTOR);
            rT_W_IDX[k].resize(MAX_NUM_KEYWORDS);
            rT_W_IDX[k].max_load_factor(KEYWORD_LOADING_FACTOR);
            rT_W_IDX[k].min_load_factor(0.0);
            rT_W_IDX[k].set_empty_key(MATRIX_ROW_SIZE+1);
            rT_W_IDX[k].set_deleted_key(MATRIX_ROW_SIZE+2);
            
            rT_F_IDX[k] = TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX(MAX_NUM_OF_FILES*FILE_LOADING_FACTOR);
            rT_F_IDX[k].resize(MAX_NUM_OF_FILES);
            rT_F_IDX[k].max_load_factor(FILE_LOADING_FACTOR);
            rT_F_IDX[k].min_load_factor(0.0);
            rT_F_IDX[k].set_empty_key(MATRIX_COL_SIZE*BYTE_SIZE+1);
            rT_F_IDX[k].set_deleted_key(MATRIX_COL_SIZE*BYTE_SIZE+2);            
        }
        
        /*
         * 1. Scan through database first to determine the size of files and unique keywords
         * 
         */
        
        printf("   1.1. Scanning through database...");
        start = time_now;
        this->scanDatabase(rFileNames,keywords_dictionary,path);
        end = time_now;
        printf("OK!\t\t %8.4f ms \n",std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count()/1000000.0);

        
        
        //stats keywords & file pairs
        //total kw_file_pair
        long int total = 0;
        for(TYPE_INDEX i = 0 ; i < Client_DSSE::kw_file_pair[0].size();i++)
        {
            total+=Client_DSSE::kw_file_pair[0][i].size();
        }
        cout<<"# unique kw: "<<keywords_dictionary.size()<<endl;
        cout<<"# unique files: "<<rFileNames.size()<<endl;
        cout<<"# keyword/file pairs: "<<total<<endl;
        if (Client_DSSE::keywords_dictionary.size()>MAX_NUM_KEYWORDS)
        {
            set<string>::iterator it = Client_DSSE::keywords_dictionary.end();
            for(TYPE_INDEX i = 0 ; i < MAX_NUM_KEYWORDS; i++)
                it--;
            Client_DSSE::keywords_dictionary.erase (Client_DSSE::keywords_dictionary.begin(), it);
        }
        cout<<"# unique kw (after remove): "<<keywords_dictionary.size()<<endl;
        
        printf("    1.2 Generating row keys...");
        start = time_now;
        this->precomputeRow_keys(pRowCounterArray,Client_DSSE::precomputed_row_key,pKey);
        end = time_now;
		printf("OK!\t\t %8.4f ms \n",std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count()/1000000.0);
        
#if !defined(LOAD_PREVIOUS_DATA_MODE)
        
        /* 
         * 2. Construct the unencrypted I (as \delta in SAC)
         */
        printf("    1.3 Creating keyword/file pairs...");
		start = time_now;
        if((ret = createKW_file_pair(rT_W, rT_F,  rT_W_IDX, rT_F_IDX, setKeywordIdx, setFileIdx, path, pKey))!=0)
        {
            printf("Error! \n");
            goto exit;
        }
		end = time_now;
		printf("OK!\t\t %8.4f ms \n",std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count()/1000000.0);
        
        total =0;
        for(TYPE_INDEX i = 0 ; i < Client_DSSE::kw_file_pair[0].size();i++)
        {
            total+=Client_DSSE::kw_file_pair[0][i].size();
        }
        cout<<"# keyword/file pairs: "<<total<<endl;
        
        cin.get();
        
        
        
        
        printf("    1.4 Writing info to disk...");
        start = time_now;
        //try to write hash table info and reload it
        Miscellaneous::writeHash_table_token(rT_W,gcsKwHashTable,gcsDataStructureFilepath);
        Miscellaneous::writeHash_table_token(rT_F,gcsFileHashTable,gcsDataStructureFilepath);
        //write list file idx & keyword idx
        for(int k = 0 ; k < NUM_SERVERS;k++)
        {
            string filename = gcsListFreeFileIdx +std::to_string(k);
            Miscellaneous::write_list_to_file(filename,gcsDataStructureFilepath,setFileIdx[k]);
            filename = gcsListFreeKwIdx +std::to_string(k);
            Miscellaneous::write_list_to_file(filename,gcsDataStructureFilepath,setKeywordIdx[k]);
            
            filename = gcsListNonFreeKwIdx +std::to_string(k);
            Miscellaneous::write_list_to_file(filename,gcsDataStructureFilepath,Client_DSSE::lstT_W_IDX[k]);
            filename = gcsListNonFreeFileIdx +std::to_string(k);
            Miscellaneous::write_list_to_file(filename,gcsDataStructureFilepath,Client_DSSE::lstT_F_IDX[k]);
        }
        end = time_now;
		printf("OK!\t\t %8.4f ms \n",std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count()/1000000.0);
        

        
        printf("    1.4 Creating encrypted matrix and write to disk...");
        start = time_now;
        this->createEncryptedMatrix_from_kw_file_pair(pColumnCounterArray);
        end = time_now;
		printf("OK!\t\t %8.4f ms \n",std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count()/1000000.0);
        
#else

        printf("    1.4 Loading info from disk...");
        start = time_now;
        rT_W.clear();
        rT_F.clear();

        Miscellaneous::readHash_table_token(rT_W,gcsKwHashTable,gcsDataStructureFilepath,keywords_dictionary.size());
        Miscellaneous::readHash_table_token(rT_F,gcsFileHashTable,gcsDataStructureFilepath,rFileNames.size());
        
        
        //rebuild rT_W_IDX and rT_F_IDX and setKeywordIdx, and setFileIdx from T_W and T_F
        TYPE_GOOGLE_DENSE_HASH_MAP::iterator it;
        TYPE_GOOGLE_DENSE_HASH_MAP::iterator it_end;
        
        for(int k = 0 ; k < NUM_SERVERS;k++)
        {
            rT_W_IDX[k].clear();
            rT_F_IDX[k].clear();
        }
        for(it = rT_W.begin(), it_end = rT_W.end(); it != it_end;it++)
        {
            hashmap_key_class tmp = it->first;
            for(int k = 0 ; k < NUM_SERVERS; k++)
            {
                TYPE_INDEX idx = it->second->getIndexBySID(k);
                rT_W_IDX[k][idx] = tmp;
            }
        }
        for(it = rT_F.begin(), it_end = rT_F.end(); it != it_end;it++)
        {
            hashmap_key_class tmp = it->first;
            for(int k = 0 ; k < NUM_SERVERS; k++)
            {
                TYPE_INDEX idx = it->second->getIndexBySID(k);
                rT_F_IDX[k][idx] = tmp;
            }
        }
    
        for(int k = 0 ; k < NUM_SERVERS;k++)
        {
            string filename = gcsListFreeFileIdx +std::to_string(k);
            Miscellaneous::read_list_from_file(filename,gcsDataStructureFilepath,setFileIdx[k]);
            filename = gcsListFreeKwIdx +std::to_string(k);
            Miscellaneous::read_list_from_file(filename,gcsDataStructureFilepath,setKeywordIdx[k]);

            filename = gcsListNonFreeKwIdx +std::to_string(k);
            Miscellaneous::read_list_from_file(filename,gcsDataStructureFilepath,Client_DSSE::lstT_W_IDX[k]);
            filename = gcsListNonFreeFileIdx +std::to_string(k);
            Miscellaneous::read_list_from_file(filename,gcsDataStructureFilepath,Client_DSSE::lstT_F_IDX[k]);
            
        }
        end = time_now;
		printf("OK!\t\t %8.4f ms \n",std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count()/1000000.0);
        
#endif        
       
#if !defined(CLIENT_SERVER_MODE)
    for(int k = 0 ; k < NUM_SERVERS; k++)
        this->loadWhole_encrypted_matrix_from_file(I[k],k);
#endif


#if defined (ENCRYPT_PHYSICAL_FILE) 
       /*
         * 4. Encrypt the files c_j
         */
        printf("   1.6. Encrypting files...");
        start_time = getCPUTime();
        //clear the folder of encrypted file path first by system call
        system(str_clear_folder_cmd.c_str());
        if((ret = fc->encryptFiles(rT_F, rFileNames, path, encrypted_files_path, pKey))!=0)
        {
            printf("error!\n");
            goto exit;
        }

		end_time = getCPUTime();
		elapsed = 1000.0 * (end_time - start_time);
		printf("OK!\t\t%g ms\n",elapsed);
#endif
		/*
         * 5. Output the I and \vec{c} by the MatrixType I param and the path of encrypted file
         *    Then, clear everything for security 
         */
	}
    catch(exception &e)
    {
		cout << "   Error occurred in dynamicsse_index_setup function " << e.what() << endl;
        ret = SETUP_DATA_STRUCTURE_ERR;
        goto exit;
	}
    ret = 0;

exit:
    delete tfunc; 
#if defined (ENCRYPT_PHYSICAL_FILE)
    str_clear_folder_cmd.clear();
    delete fc; 
#endif

	return ret;
}


int DSSE::createKW_file_pair(
		TYPE_GOOGLE_DENSE_HASH_MAP &rT_W,
		TYPE_GOOGLE_DENSE_HASH_MAP &rT_F,
        TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX rT_W_IDX[NUM_SERVERS],
        TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX rT_F_IDX[NUM_SERVERS],
        vector<TYPE_INDEX> setKeywordIdx[NUM_SERVERS],
        vector<TYPE_INDEX> setFileIdx[NUM_SERVERS],
		string path,
		MasterKey *pKey)
{
	int keyword_len = 0, bit_position=0;
    int ret;
	TYPE_INDEX row = 0, col =0, file_index = 0, keyword_index = 0;
	unsigned char keyword_trapdoor[TRAPDOOR_SIZE];
	unsigned char file_trapdoor[TRAPDOOR_SIZE];
	string word;
	DIR *pDir;
	struct dirent *pEntry;
	struct stat file_stat;
	string file_name, file_name_with_path;
	TYPE_KEYWORD_DICTIONARY words_per_file;
	set<string>::iterator iter;

    KeywordExtraction* kw_ex = new KeywordExtraction();
    DSSE_Trapdoor* dsse_trapdoor = new DSSE_Trapdoor();
    bool randomBit;
    TYPE_INDEX randomNumber;
    try
    {
		if((pDir=opendir(path.c_str())) != NULL)
        {
			while((pEntry = readdir(pDir))!=NULL)
            {
				file_name = pEntry->d_name;
                // look into pEntry 
				if(!file_name.compare(".") || !file_name.compare("..")) {
					continue;
				}
				else{
					file_name_with_path = path + pEntry->d_name;                                      // "/" +
					// If the file is a directory (or is in some way invalid) we'll skip it
					if (stat(file_name_with_path.c_str(), &file_stat)) 
                        continue;
                        
					if (S_ISDIR(file_stat.st_mode)){
						file_name_with_path.append("/");

						createKW_file_pair(rT_W, rT_F, rT_W_IDX, rT_F_IDX, setKeywordIdx, setFileIdx, file_name_with_path, pKey);

						continue;
					}
					if(file_name_with_path.size() > 0)
                    {
						if((ret = dsse_trapdoor->generateTrapdoor_single_input(file_trapdoor, TRAPDOOR_SIZE,	
								(unsigned char *)file_name_with_path.c_str(), 
								file_name_with_path.size(), pKey))!=0)
                        {
                            goto exit;
                        }
                    }
					else
						printf("File name is empty\n");

					hashmap_key_class hmap_file_trapdoor(file_trapdoor,TRAPDOOR_SIZE);
                    
					// Get the file index from the hashmap
                    /* 
                    * Init the counter value for this file as 1
                    * Added by: Thang Hoang - 2015-11-06
                    */
                    
                    /* ACSAC */
                    if(rT_F[hmap_file_trapdoor] == NULL)
                    {
                        rT_F[hmap_file_trapdoor] = new TokenInfo();
                        for ( int i = 0 ; i < NUM_SERVERS;i++)
                        {
                            TYPE_INDEX selectedIdx;
                            this->getRandomElement(selectedIdx,setFileIdx[i]);
                            rT_F[hmap_file_trapdoor]->setIndex(selectedIdx,i);
                            //also build hash table for index for O(1) index lookup
                            rT_F_IDX[i][selectedIdx] = hmap_file_trapdoor;
                            
                            //store the selected index in array for fast online computation
                            Client_DSSE::lstT_F_IDX[i].push_back(selectedIdx);
                        }
                        this->genRandomNumber(randomNumber,2);
                        randomBit = static_cast<bool>(randomNumber);
                        rT_F[hmap_file_trapdoor]->setServerID(randomBit);
                    }	
                    if(rT_F.bucket_count()*rT_F.load_factor()>MAX_NUM_OF_FILES)
                    {
                        printf("Not enough memory to handle more file!\n");
                        ret = MAX_FILE_INDEX_EXCEEDED_ERR;
                        goto exit;
                    }
                    
					if((ret = kw_ex->extractKeywords(words_per_file, file_name, path))!=0)
                    {
                        goto exit;
                    }
                    
                    for(iter=words_per_file.begin();iter != words_per_file.end();iter++) 
                    {
						word = *iter;
						keyword_len = word.size();
                        /* if the keyword is NOT in the set of keyword dictionary, SKIP it */
                        if(Client_DSSE::keywords_dictionary.find(word)==Client_DSSE::keywords_dictionary.end())
                            continue;
                        if(keyword_len>0)
                        {
							if((ret = dsse_trapdoor->generateTrapdoor_single_input(keyword_trapdoor, TRAPDOOR_SIZE, 
									(unsigned char *)word.c_str(), keyword_len, pKey))!=0)
                            {
                                goto exit;
                            }
                        }
						else
                        {
                            continue;
                        }
						hashmap_key_class hmap_keyword_trapdoor(keyword_trapdoor,
																TRAPDOOR_SIZE);
                 		
                        /* ACSAC */
                        if(rT_W[hmap_keyword_trapdoor] == NULL)
                        {
                            rT_W[hmap_keyword_trapdoor] = new TokenInfo();
                            for ( int i = 0 ; i < NUM_SERVERS;i++)
                            {
                                TYPE_INDEX selectedIdx;
                                this->getRandomElement(selectedIdx,setKeywordIdx[i]);
                                rT_W[hmap_keyword_trapdoor]->setIndex(selectedIdx,i);
                                
                                //also build hash table for index for O(1) index lookup
                                rT_W_IDX[i][selectedIdx] = hmap_keyword_trapdoor;
                                
                                //store the selected index in array for fast online computation
                                Client_DSSE::lstT_W_IDX[i].push_back(selectedIdx);
                            }
                            this->genRandomNumber(randomNumber,2);
                            randomBit = static_cast<bool>(randomNumber);
                            rT_W[hmap_keyword_trapdoor]->setServerID(randomBit);
                            
                        }
                        /* --ACSAC-- */
                        
                        if(rT_W.bucket_count()*rT_W.load_factor()>MAX_NUM_KEYWORDS)
                        {
                            ret = MAX_KEYWORD_INDEX_EXCEEDED_ERR;
                            printf("Not enough memory to handle more keywords!\n");
                            goto exit;
                        }
						// If the keyword is in the file, set the bit position for a given row & col value
                        for(int k = 0 ; k < NUM_SERVERS; k++)
                        {
                            row = rT_W[hmap_keyword_trapdoor]->getIndexBySID(k);
                            file_index = rT_F[hmap_file_trapdoor]->getIndexBySID(k);
                            //build the keyword file pair
                            Client_DSSE::kw_file_pair[k][file_index].push_back(row);
                        }
						// Clearing contents
						word.clear();
					}
					// Clearing contents
					words_per_file.clear();
					file_name_with_path.clear();
				}
				// Clearing contents
				file_name.clear();
			}

			closedir(pDir);
		}

		else{
			printf("Could not locate the directory...\n");
		}
	}
    catch(exception &e)
    {
        ret = INITIALIZE_MATRIX_ERR;
		cout << "Error occurred in initializeMatrix function " << e.what() << endl;
        goto exit;
	}
    ret = 0;
    
exit:
    memset(keyword_trapdoor,0,TRAPDOOR_SIZE);
	memset(file_trapdoor,0,TRAPDOOR_SIZE);
	word.clear();
	delete pEntry;
	file_name.clear(); 
    file_name_with_path.clear();
	words_per_file.clear();
	delete kw_ex;
    delete dsse_trapdoor;
	
    return ret;
}
int DSSE::getRandomElement(TYPE_INDEX &random_element, vector<TYPE_INDEX> &setIdx)
{
    int ret = 0;
    
    TYPE_INDEX random_idx;
    this->genRandomNumber(random_idx,setIdx.size());
    
    random_element = setIdx[random_idx];
    setIdx.erase(setIdx.begin()+random_idx);
    
    return ret;
}
int DSSE::genRandomNumber(TYPE_INDEX &output, TYPE_INDEX size)
{
    int ret = 0;
    unsigned char pseudo_random_number [BLOCK_CIPHER_SIZE];
    int seed_len = BLOCK_CIPHER_SIZE ; // how much is enough ? 4 + 1
	int error = 0;
   
    unsigned char *pSeed = new unsigned char[seed_len];
    TYPE_INDEX tmp;
    DSSE_KeyGen* dsse_keygen = new DSSE_KeyGen();
    memset(pseudo_random_number,0,BLOCK_CIPHER_SIZE);               
    
	//	Generating random seed needed for calling fortuna PRNG
	if ((error = dsse_keygen->rdrand(pSeed,seed_len, RDRAND_RETRY_NUM)) != CRYPT_OK) {
		printf("Error calling rdrand_get_n_units_retry: %d\n", error/*error_to_string(error)*/);
		ret = KEY_GENERATION_ERR;
        goto exit;
	}
    // Generate random number 
	if ((error = dsse_keygen->invokeFortuna_prng(pSeed, pseudo_random_number, seed_len, BLOCK_CIPHER_SIZE)) != CRYPT_OK) {
		printf("Error calling call_fortuna_prng function: %d\n", error/*error_to_string(error)*/);
		ret = KEY_GENERATION_ERR;
        goto exit;
	}
    
    memcpy(&tmp,&pseudo_random_number[7],sizeof(tmp)); // lay nua sau cua pseudo random number
    output = tmp % size;

exit:
    memset(pSeed,0,seed_len);
    delete dsse_keygen;
    delete pSeed;
    memset(pseudo_random_number,0,BLOCK_CIPHER_SIZE);
    return ret;
}

int DSSE::genToken(OPERATION_TOKEN &operation_token, int op,
		string strInput,
        vector<TYPE_INDEX> setDummy_idx[NUM_SERVERS],
        TYPE_GOOGLE_DENSE_HASH_MAP &rT, 
        MasterKey *pKey)
{
    int ret;
	unsigned char input_trapdoor[TRAPDOOR_SIZE] = {'\0'};
    DSSE_Trapdoor* dsse_trapdoor = new DSSE_Trapdoor();
    TYPE_INDEX random_idx;
    
    bool b, neg_b ;
    TYPE_GOOGLE_DENSE_HASH_MAP::iterator it;
    hashmap_key_class key_b, key_negb;
	try
    {
        /* 
         * 1. Generates the trapdoor for the strInput
         * 
         * */
        int input_length = strlen(strInput.c_str());
        if(input_length >0)
        {
            if((ret = dsse_trapdoor->generateTrapdoor_single_input(input_trapdoor, TRAPDOOR_SIZE, (unsigned char *)strInput.c_str(), input_length, pKey))!=0)
            {
                goto exit;
            }
        }        
        // Typecast strInput trapdoor to hashmap entry type (hashmap_key_class)
        hashmap_key_class hmap_input_trapdoor(input_trapdoor, TRAPDOOR_SIZE);
        /*
         * 2. Get the strInput index from the hashmap if the strInput exists in the hash table
         */
        if(rT[hmap_input_trapdoor]==NULL || input_length == 0) 
        {
            if(op==OP_ADD_FILE)
            {
                rT[hmap_input_trapdoor] = new TokenInfo();
                for ( int i = 0 ; i < NUM_SERVERS;i++)
                {
                    TYPE_INDEX selectedIdx;
                    this->getRandomElement(selectedIdx,setDummy_idx[i]);
                    rT[hmap_input_trapdoor]->setIndex(selectedIdx,i);
                }
                this->genRandomNumber(random_idx,2);
                int random_bit = static_cast<bool>(random_idx);
                rT[hmap_input_trapdoor]->setServerID(random_bit);
                
                b = rT[hmap_input_trapdoor]->getServerID();
                neg_b = (b+1) % 2;
                operation_token.b = b;
                operation_token.nonempty_add[b] = hmap_input_trapdoor;
                operation_token.isRealQuery = true;
            }	
            else //// Doc bat ki row nao trong rT_W
            {
                rT.erase(hmap_input_trapdoor);
                this->genRandomNumber(random_idx,rT.load_factor()*rT.bucket_count()); //-1 because the trapdoor for this fake string has just been included right before.
                it = rT.begin(); 
                for (TYPE_INDEX i = 0 ; i < random_idx;i++)
                {
                    ++it;
                }
                key_b = it->first;
                b = rT[key_b]->getServerID();
                neg_b = (b+1) %2 ;
                operation_token.nonempty_add[b] = key_b;
                operation_token.b = b;
                operation_token.isRealQuery = false;
            }
        }
        else
        {
            b = rT[hmap_input_trapdoor]->getServerID();
            neg_b = (b+1) % 2;
            operation_token.b = b;
            operation_token.nonempty_add[b] = hmap_input_trapdoor;
            operation_token.isRealQuery = true;
        } 
        /*
         * 3. Generate a random index in the set of available indices 
         * */
        
        this->genRandomNumber(random_idx,setDummy_idx[b].size());
        operation_token.empty_add[b] = setDummy_idx[b][random_idx];
        
        
        /* 
         * 4. Generate two random indeces from neg B server, including 1 from rT (EXCLUDING THE ONE SELECTED BEFORE) and 1 from empty address
         * */
        do
        {
            this->genRandomNumber(random_idx,rT.load_factor()*rT.bucket_count());
            it = rT.begin(); 
            for (TYPE_INDEX i = 0 ; i < random_idx;i++)
                ++it;
            key_negb = it->first;
            operation_token.nonempty_add[neg_b] = key_negb;
            if (memcmp(key_negb.get_data(),operation_token.nonempty_add[b].get_data(),TRAPDOOR_SIZE)!=0)
                break;
        }while(1);        
        this->genRandomNumber(random_idx,setDummy_idx[neg_b].size());
        operation_token.empty_add[neg_b] = setDummy_idx[neg_b][random_idx];
        
    
    }
    catch(exception &e)
    {
		cout << "     Error occured in generateOperationToken function " << e.what() << endl;
        //ret = ENCRYPT_DATA_STRUCTURE_ERR;
        goto exit;
    }
    ret = 0;

exit:
    memset(input_trapdoor,0,TRAPDOOR_SIZE);
    delete dsse_trapdoor;
	return ret;
}


int DSSE::setBlock(TYPE_INDEX index,    //input
                        int op,              //input
                        MatrixType** I,             //input & output
                        MatrixType* I_prime)       //input
{
    TYPE_INDEX row, col, idx;
    TYPE_INDEX I_prime_col;
    TYPE_INDEX I_prime_bit_position;
    int bit_position;
    int bit_value;
    int ret;
    try
    {
        if(op == COL_DATA)
        {
            col = index / BYTE_SIZE;
            bit_position = index % BYTE_SIZE;
            idx = 0;
            for (I_prime_col = 0 ; I_prime_col < MATRIX_ROW_SIZE/BYTE_SIZE; I_prime_col++)
            {
                for(I_prime_bit_position=0 ; I_prime_bit_position<BYTE_SIZE; I_prime_bit_position++)
                {
                    BIT_CLEAR(&I[I_prime_col*BYTE_SIZE+I_prime_bit_position][col].byte_data,bit_position);
                    if(BIT_CHECK(&I_prime[I_prime_col].byte_data,I_prime_bit_position))
                    {
                        BIT_SET(&I[I_prime_col*BYTE_SIZE+I_prime_bit_position][col].byte_data,bit_position);
                    }
                    
                }
            }
        }
        else
        {
            memcpy(I[index],I_prime,MATRIX_COL_SIZE);
        }
    }    
    catch(exception &e)
    {
		cout << "Error occured in setBlock_data function " << e.what() << endl;
        ret = FETCH_BLOCK_DATA_ERR;
        goto exit;
    }
    ret = 0;
exit:
    return ret;                       
}
int DSSE::getBlock( TYPE_INDEX index,    //input
                        int op,              //input
                        MatrixType** I,             //input
                        MatrixType* I_prime)       //output
{
    TYPE_INDEX row, col, idx;
    TYPE_INDEX I_prime_col, I_prime_bit_position;
    int bit_position;
    int bit_value;
    int ret;
    try
    {
        if(op==COL_DATA)
        {
            col = index / BYTE_SIZE;
            bit_position = index % BYTE_SIZE;
            for (row = 0; row < MATRIX_ROW_SIZE; row++)
            {
                I_prime_col = row / BYTE_SIZE;
                I_prime_bit_position = row % BYTE_SIZE;
                if(BIT_CHECK(&I[row][col].byte_data,bit_position))
                {
                    BIT_SET(&I_prime[I_prime_col].byte_data,I_prime_bit_position);
                }
            }
        }
        else
        {
            memcpy(I_prime,I[index],MATRIX_COL_SIZE);
        }
    }    
    catch(exception &e)
    {
		cout << "Error occured in getBlock_data function " << e.what() << endl;
        ret = FETCH_BLOCK_DATA_ERR;
        goto exit;
    }
    ret = 0;
exit:
    return ret;
}

int DSSE::encBlock(MatrixType *I,  //input & output
                        int op,
                        int serverID,
                        TYPE_INDEX idx,
                        TYPE_COUNTER counter,   
                        TYPE_COUNTER counter_arr[],
                        MatrixType *I_prime,
                        MasterKey *pKey)
{
    int ret;
	TYPE_INDEX row,col = 0;
    unsigned char uchar_counter[BLOCK_CIPHER_SIZE];
    unsigned char U[BLOCK_CIPHER_SIZE];
    unsigned char V[BLOCK_CIPHER_SIZE];
    unsigned char row_key_input[BLOCK_CIPHER_SIZE];
    unsigned char row_key[BLOCK_CIPHER_SIZE];
    unsigned char bit_number;
    TYPE_INDEX col_idx;
    int bit_value;
    MatrixType tmp_byte;
    Miscellaneous misc;
    
    DSSE_KeyGen* dsse_keygen = new DSSE_KeyGen();
    if(op == ROW_DATA)
    {
        // Generate the row key
        memset(row_key,0,sizeof(row_key));
        memset(row_key_input,0,sizeof(row_key_input));
        memcpy(row_key_input,&idx,sizeof(idx));
        memcpy(&row_key_input[BLOCK_CIPHER_SIZE/2],&counter,sizeof(counter));
       if((ret = dsse_keygen->genRow_key(row_key, BLOCK_CIPHER_SIZE, row_key_input, BLOCK_CIPHER_SIZE, serverID, pKey))!=0)
        {
            goto exit;
        }
    
        // For each block
        for(col=0;col<MATRIX_COL_SIZE;col++)
        {
            for(bit_number = 0 ; bit_number < BYTE_SIZE; bit_number++)
            {
                memset(V,0,sizeof(V));
                memset(U,0,sizeof(U));
                
                // Reads the bit value
                BIT_READ(&I[col].byte_data,bit_number,&bit_value);

                if(bit_value)
                {
                    U[0] = FIRST_BIT_ONE;
                }
                
                // Get the block index of this current block
                col_idx = col*BYTE_SIZE + bit_number;
                    
                memset(uchar_counter,0,BLOCK_CIPHER_SIZE);
                memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&counter_arr[col_idx],sizeof(TYPE_COUNTER));
                memcpy(&uchar_counter,&col_idx,sizeof(TYPE_INDEX));
                // Encrypting the matrix I using AES CTR 128 function
                aes128_ctr_encdec(U, V, row_key, uchar_counter, ONE_VALUE);
                
                // Write the encryped row back to matrix I
                BIT_READ(&V[0],BIT_POS,&bit_value);
                if(bit_value)
                {
                    bit_field_access(I_prime,col,bit_number);
                }
                else
                {
                    bit_field_reset(I_prime,col,bit_number);
                }
                //Read the row data from matrix I for the current block
            }
        }
    }
    else
    {
        for(row = 0 ; row < MATRIX_ROW_SIZE;row++)
        {
            col = row / BYTE_SIZE;
            bit_number = row % BYTE_SIZE;
            
            // Generate the row key
            memset(row_key,0,sizeof(row_key));
            memset(row_key_input,0,sizeof(row_key_input));
            memcpy(row_key_input,&row,sizeof(row));
            memcpy(&row_key_input[BLOCK_CIPHER_SIZE/2],&counter_arr[row],sizeof(counter_arr[row]));
        
            if((ret = dsse_keygen->genRow_key(row_key, BLOCK_CIPHER_SIZE, row_key_input, BLOCK_CIPHER_SIZE, serverID, pKey))!=0)
            {
                goto exit;
            }
            memset(V,0,sizeof(V));
            memset(U,0,sizeof(U));
                
            // Reads the bit value
            BIT_READ(&I[col].byte_data,bit_number,&bit_value);

            if(bit_value)
            {
                U[0] = FIRST_BIT_ONE;
            }
        
            memset(uchar_counter,0,BLOCK_CIPHER_SIZE);
            memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&counter,sizeof(TYPE_COUNTER));
            memcpy(&uchar_counter,&idx,sizeof(TYPE_INDEX));
            // Encrypting the matrix I using AES CTR 128 function
     
            aes128_ctr_encdec(U, V, row_key, uchar_counter, ONE_VALUE);
            
            // Write the encryped row back to matrix I
            BIT_READ(&V[0],BIT_POS,&bit_value);
            if(bit_value)
            {
                bit_field_access(I_prime,col,bit_number);
            }
            else
            {
                bit_field_reset(I_prime,col,bit_number);
            }
        }
    }
   
exit:
    return ret;
}
int DSSE::decBlock(MatrixType *I,  //input & output
                        int op,
                        int serverID,
                        TYPE_INDEX idx,
                        TYPE_COUNTER counter,   
                        TYPE_COUNTER counter_arr[],
                        MatrixType *I_prime,
                        TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX &rT_IDX, //this is used to decrypt only valid address ->accelerate the speed into twice!
                        MasterKey *pKey)
{
    int ret;
	TYPE_INDEX row,col = 0;
    unsigned char uchar_counter[BLOCK_CIPHER_SIZE];
    unsigned char U[BLOCK_CIPHER_SIZE];
    unsigned char V[BLOCK_CIPHER_SIZE];
    unsigned char row_key_input[BLOCK_CIPHER_SIZE];
    unsigned char row_key[BLOCK_CIPHER_SIZE];
    unsigned char bit_number;
    TYPE_INDEX col_idx;
    int bit_value;
    MatrixType tmp_byte;
    Miscellaneous misc;
    
    DSSE_KeyGen* dsse_keygen = new DSSE_KeyGen();
    TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX::iterator it;
    if(op == ROW_DATA)
    {
        // Generate the row key
        memset(row_key,0,sizeof(row_key));
        memset(row_key_input,0,sizeof(row_key_input));
        memcpy(row_key_input,&idx,sizeof(idx));
        memcpy(&row_key_input[BLOCK_CIPHER_SIZE/2],&counter,sizeof(counter));
        
        if((ret = dsse_keygen->genRow_key(row_key, BLOCK_CIPHER_SIZE, row_key_input, BLOCK_CIPHER_SIZE, serverID, pKey))!=0)
        {
            goto exit;
        }
        TYPE_INDEX lll = 0;
        // For each block
        for(it = rT_IDX.begin();it!=rT_IDX.end();it++)
        {
            
            col = it->first/BYTE_SIZE;
            bit_number = it->first%BYTE_SIZE;
            
            memset(V,0,sizeof(V));
            memset(U,0,sizeof(U));
                
            // Reads the bit value
            BIT_READ(&I[col].byte_data,bit_number,&bit_value);
            if(bit_value)
            {
                U[0] = FIRST_BIT_ONE;
            }
                
            // Get the block index of this current block
            col_idx = col*BYTE_SIZE + bit_number;
                
            memset(uchar_counter,0,BLOCK_CIPHER_SIZE);
            memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&counter_arr[col_idx],sizeof(TYPE_COUNTER));
            memcpy(&uchar_counter,&col_idx,sizeof(TYPE_INDEX));
            // Encrypting the matrix I using AES CTR 128 function
            aes128_ctr_encdec(U, V, row_key, uchar_counter, ONE_VALUE);
            
            // Write the encryped row back to matrix I
            BIT_READ(&V[0],BIT_POS,&bit_value);
            if(bit_value)
            {
                bit_field_access(I_prime,col,bit_number);
            }
            else
            {
                bit_field_reset(I_prime,col,bit_number);
            }
        }
    }
    else
    {
        for(it = rT_IDX.begin();it!=rT_IDX.end();it++)
        {
            row = it->first;
            col = row / BYTE_SIZE;
            bit_number = row % BYTE_SIZE;
            
            // Generate the row key
            memset(row_key,0,sizeof(row_key));
            memset(row_key_input,0,sizeof(row_key_input));
            memcpy(row_key_input,&row,sizeof(row));
            memcpy(&row_key_input[BLOCK_CIPHER_SIZE/2],&counter_arr[row],sizeof(counter_arr[row]));
        
            if((ret = dsse_keygen->genRow_key(row_key, BLOCK_CIPHER_SIZE, row_key_input, BLOCK_CIPHER_SIZE, serverID, pKey))!=0)
            {
                goto exit;
            }
        
            memset(V,0,sizeof(V));
            memset(U,0,sizeof(U));
                
            // Reads the bit value
            BIT_READ(&I[col].byte_data,bit_number,&bit_value);

            if(bit_value)
            {
                U[0] = FIRST_BIT_ONE;
            }
        
            memset(uchar_counter,0,BLOCK_CIPHER_SIZE);
            memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&counter,sizeof(TYPE_COUNTER));
            memcpy(&uchar_counter,&idx,sizeof(TYPE_INDEX));
            // Encrypting the matrix I using AES CTR 128 function
            aes128_ctr_encdec(U, V, row_key, uchar_counter, ONE_VALUE);
            
            // Write the encryped row back to matrix I
            BIT_READ(&V[0],BIT_POS,&bit_value);
            if(bit_value)
            {
                bit_field_access(I_prime,col,bit_number);
            }
            else
            {
                bit_field_reset(I_prime,col,bit_number);
            }
        }
    }
   
exit:
    return ret;
}
int DSSE::updateT(  OperationToken operation_token,
                    vector<TYPE_INDEX> setIdx[NUM_SERVERS], 
                    TYPE_COUNTER* counter_arr[NUM_SERVERS], 
                    TYPE_GOOGLE_DENSE_HASH_MAP &rT,
                    TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX rT_IDX[NUM_SERVERS],
                    vector<TYPE_INDEX> lstT_IDX[NUM_SERVERS]                //not important params, delete later
                    )
{
    TYPE_INDEX random_idx=0;
    TYPE_INDEX need_empty_add[NUM_SERVERS];
    TYPE_INDEX need_nonempty_add[NUM_SERVERS];
    
    for(int k = 0 ; k < NUM_SERVERS; k++)
    {
        int negk = (k+1)%2;
        need_empty_add[k] = rT[operation_token.nonempty_add[negk]]->getIndexBySID(k);
        need_nonempty_add[k] = operation_token.empty_add[k];
    }
    for(int k = 0 ; k < NUM_SERVERS ; k ++)
    {
        int negk = (k +1) % 2;
        rT[operation_token.nonempty_add[k]]->setIndex(need_nonempty_add[negk],negk);
        
        setIdx[k].erase(std::remove(setIdx[k].begin(),setIdx[k].end(), need_nonempty_add[k]),setIdx[k].end());
        
        this->genRandomNumber(random_idx,setIdx[k].size());
        setIdx[k].insert(setIdx[k].begin()+random_idx,need_empty_add[k]);
        
        // update the server ID
        rT[operation_token.nonempty_add[k]]->setServerID(negk);
        
        //update the index hash table
        rT_IDX[negk][need_nonempty_add[negk]] = operation_token.nonempty_add[k];
        rT_IDX[k].erase(need_empty_add[k]);


        //update the counter increasing to 1
//#if !defined(CLIENT_SERVER_MODE)
        counter_arr[k][operation_token.empty_add[k]]+=1;
        counter_arr[k][rT[operation_token.nonempty_add[k]]->getIndexBySID(k)] +=1;
//#endif
        
        // update the list of index - JUST TO MEASURE THE PERFORMANCE , NOT IMPORTATNT - DELETE LATER
        lstT_IDX[k].erase(std::remove(lstT_IDX[k].begin(),lstT_IDX[k].end(), need_empty_add[k]),lstT_IDX[k].end());
        lstT_IDX[k].push_back(need_nonempty_add[k]);
    }
}

int DSSE::genBlock_from_key(vector<hashmap_key_class> input, int serverID, int op,
                                    MatrixType *output)
{
    int ret;
    int bit_position;
    TYPE_INDEX col;
    TYPE_INDEX cur;
    TYPE_INDEX size = input.size();
    for(TYPE_INDEX i = 0 ; i < size;i++)
    {
        if(op == SEARCH_OPERATION)
            cur = Client_DSSE::T_F[input[i]]->getIndexBySID(serverID);
        else
            cur = Client_DSSE::T_W[input[i]]->getIndexBySID(serverID);
        col = cur / BYTE_SIZE;
        bit_position = cur % BYTE_SIZE;
        this->bit_field_access(output,col,bit_position);
    }
    ret = 0;
    return ret;
}
//this function only updates the decrypted row/ or col with the new index of col/ row
int DSSE::updateBlock(MatrixType* I,
                    TYPE_INDEX empty_idx,
                    TYPE_INDEX old_idx_of_new_data)
{
    int ret = 0;
    TYPE_INDEX col = old_idx_of_new_data / BYTE_SIZE;
    TYPE_INDEX bit_position = old_idx_of_new_data % BYTE_SIZE;
    
    TYPE_INDEX empty_col = empty_idx / BYTE_SIZE;
    TYPE_INDEX empty_bit_position = empty_idx % BYTE_SIZE;
    
    if(BIT_CHECK(&I[col].byte_data,bit_position))
        BIT_SET(&I[empty_col].byte_data,empty_bit_position);
    else
        BIT_CLEAR(&I[empty_col].byte_data,empty_bit_position);
    BIT_CLEAR(&I[col].byte_data,bit_position);
    
    return ret;
    
}
int DSSE::encryptData_structure(MatrixType **I, int serverID,
                    TYPE_COUNTER *pRowCounterArray,
                    TYPE_COUNTER *pColumnCounterArray,
                    MasterKey *pKey){

	// cout << "Entering encrypt_matrix function" << endl << endl;

	TYPE_INDEX row = 0, col = 0;
                
    TYPE_COUNTER keyword_counter;
    
	unsigned char row_key[BLOCK_CIPHER_SIZE];
    unsigned char uchar_counter[BLOCK_CIPHER_SIZE];
	
    unsigned char U[BLOCK_CIPHER_SIZE]; // size of U should be a block ( b = 128 bit = 16 bytes)
    unsigned char V[BLOCK_CIPHER_SIZE]; // size of V should be a block ( b = 128 bit = 16 bytes)
        
    unsigned char row_key_input[BLOCK_CIPHER_SIZE];
    
    DSSE_KeyGen* dsse_keygen = new DSSE_KeyGen(); 
    Miscellaneous misc;
    
    
    int bit_number,bit_value;
    TYPE_INDEX col_index;
                    
    int ret;
    // NULL checks
	if(pKey->isNULL())
    {
        printf("Key empty!\n");
        ret = KEY_NULL_ERR; 
        goto exit;
    }
	try
    {
        /*
         * -- Step 3(b,c) Encrypt the matrix I
         * */
        for(row=0;row<MATRIX_ROW_SIZE;row++)
        {
            /*
             * 3.b. Generate the rowkey r_i 
             * */
			keyword_counter = pRowCounterArray[row];
            
            memset(row_key_input,0,sizeof(row_key_input));
            memcpy(row_key_input,&row,sizeof(row));
            memcpy(&row_key_input[BLOCK_CIPHER_SIZE/2],&keyword_counter,sizeof(keyword_counter));
            
            if((ret = dsse_keygen->genRow_key(row_key, BLOCK_CIPHER_SIZE, row_key_input, BLOCK_CIPHER_SIZE, serverID, pKey))!=0)
            {
                goto exit;
            }
            /*
             * Read data from matrix I block by block and encrypt block by block for each row
             */
            for(col = 0 ; col < MATRIX_COL_SIZE;col++)
            {
                for(bit_number = 0;bit_number<BYTE_SIZE;bit_number++)
                {
                    memset(U,0,sizeof(U));
                    memset(V,0,sizeof(V));
                    
                    // Reads the bit value
                    if(BIT_CHECK(&I[row][col].byte_data,bit_number))
                        BIT_SET(&U[0],0);
                    // Get the block index of this current block
                    col_index = col*BYTE_SIZE + bit_number;
                    
                    memset(uchar_counter,0,BLOCK_CIPHER_SIZE);
                    memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&pColumnCounterArray[col_index],sizeof(TYPE_COUNTER));
                    memcpy(&uchar_counter,&col_index,sizeof(TYPE_INDEX));
                    // Encrypting the  matrix I using AES CTR 128 function
                    aes128_ctr_encdec(U, V, row_key, uchar_counter, ONE_VALUE);
                
                    // Write the encryped row back to matrix I
                    if(BIT_CHECK(&V[0],0))
                        bit_field_access(I,row,col,bit_number);
                    else
                    {
                        bit_field_reset(I,row,col,bit_number);
                    }
                }
            }
		}
	}
    catch(exception &e)
    {
		cout << "     Error occured in encryptData_structure function " << e.what() << endl;
        ret = ENCRYPT_DATA_STRUCTURE_ERR;
        goto exit;
    }
    ret = 0;


exit:
	memset(row_key,0,BLOCK_CIPHER_SIZE);
    memset(uchar_counter,0,BLOCK_CIPHER_SIZE);
    memset(U,0,BLOCK_CIPHER_SIZE); 
    memset(V,0,BLOCK_CIPHER_SIZE);
    memset(row_key_input,0,BLOCK_CIPHER_SIZE);
    
    delete dsse_keygen;
    
    return ret;
}



int DSSE::getKey_from_block(MatrixType* I, int op, int serverID,
                                vector<hashmap_key_class> &lstKey, 
                                vector<TYPE_INDEX> setDummy_idx)
{
    TYPE_INDEX col;
    int bit_position;
    int bit_value;
    TYPE_GOOGLE_DENSE_HASH_MAP::iterator it;
    Miscellaneous misc;
    TYPE_INDEX size, idx;
    if(op == ROW_DATA)
        size = MATRIX_COL_SIZE;
    else
        size = MATRIX_ROW_SIZE/BYTE_SIZE;
    //filter dummy indices;
    TYPE_INDEX set_size = setDummy_idx.size();
    lstKey.reserve(MATRIX_ROW_SIZE);
    for (TYPE_INDEX i = 0 ; i < set_size ; i ++)
    {
        bit_position = (setDummy_idx[i]%BYTE_SIZE);
        col = setDummy_idx[i] / BYTE_SIZE;
        BIT_CLEAR(&I[col].byte_data,bit_position);
    }
    for (col = 0 ; col < size; col ++)
    {
        for(bit_position = 0 ; bit_position < BYTE_SIZE ; bit_position++)
        {
            if(BIT_CHECK(&I[col].byte_data,bit_position))
            {
                idx = col*BYTE_SIZE + bit_position;
                if(op==SEARCH_OPERATION)
                    lstKey.push_back(Client_DSSE::T_F_IDX[serverID][idx]);
                else
                    lstKey.push_back(Client_DSSE::T_W_IDX[serverID][idx]);
            }
        }
    }
    return 0;
}

int DSSE::bit_field_access(MatrixType *I,
		TYPE_INDEX col,
		int bit_position)
{
    int ret;
    try
    {
        switch(bit_position)
        {
        case 0: I[col].bit_data.bit1 = 1;
        break;

        case 1: I[col].bit_data.bit2 = 1;
        break;

        case 2: I[col].bit_data.bit3 = 1;
        break;

        case 3: I[col].bit_data.bit4 = 1;
        break;

        case 4: I[col].bit_data.bit5 = 1;
        break;

        case 5: I[col].bit_data.bit6 = 1;
        break;

        case 6: I[col].bit_data.bit7 = 1;
        break;

        case 7: I[col].bit_data.bit8 = 1;
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
int DSSE::bit_field_reset(MatrixType *I,
		TYPE_INDEX col,
		int bit_position)
{
    int ret;
    try
    {
        switch(bit_position)
        {
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

int DSSE::genUpdate_lstKey_from_file(string filename_with_path, int op, 
                                    vector<hashmap_key_class> &lstKey, //outputs
                                    TYPE_GOOGLE_DENSE_HASH_MAP &rT_W,
                                    vector<TYPE_INDEX> setDummy_keyword_idx[NUM_SERVERS],
                                    MasterKey* pKey
                                    )
{
    DSSE_Trapdoor* dsse_trapdoor = new DSSE_Trapdoor();
    TYPE_INDEX idx;
    TYPE_INDEX random_number;
    int random_bit;
    KeywordExtraction* kw_ex = new KeywordExtraction();
    TYPE_KEYWORD_DICTIONARY::iterator iter;
    unsigned char keyword_trapdoor[TRAPDOOR_SIZE] = {'\0'};
    int bit_position;
    int ret;
    TYPE_KEYWORD_DICTIONARY extracted_keywords;
    lstKey.clear();
    
    if(op == OP_ADD_FILE)
    {
        /*
         * 1. Extract words from file
         *
         * */
        if((ret = kw_ex->extractKeywords(extracted_keywords, filename_with_path, ""))!=0)
        {
            goto exit;
        }
        for(iter=extracted_keywords.begin();iter != extracted_keywords.end();iter++) 
        {
            string word = *iter;
            int keyword_len = word.size();

            if(keyword_len>0)
            {
                if((ret = dsse_trapdoor->generateTrapdoor_single_input(keyword_trapdoor, TRAPDOOR_SIZE, 
                                        (unsigned char *)word.c_str(), keyword_len, pKey))!=0)
                {
                    goto exit;
                }
            }
            else
                printf( "File name is empty\n");
            hashmap_key_class hmap_keyword_trapdoor(keyword_trapdoor, TRAPDOOR_SIZE);
            /* ACSAC */
            if(rT_W[hmap_keyword_trapdoor] == NULL)
            {
                     /* --ACSAC-- */
                if(rT_W.bucket_count()>MAX_NUM_KEYWORDS)
                {
                    ret = MAX_KEYWORD_INDEX_EXCEEDED_ERR;
                    printf("Not enough memory to handle more keywords!\n");
                    goto exit;
                }
                rT_W[hmap_keyword_trapdoor] = new TokenInfo();
                for ( int i = 0 ; i < NUM_SERVERS;i++)
                {
                    TYPE_INDEX selectedIdx;
                    this->getRandomElement(selectedIdx,setDummy_keyword_idx[i]);
                    rT_W[hmap_keyword_trapdoor]->setIndex(selectedIdx,i);
                }
                this->genRandomNumber(random_number,2);
                random_bit = static_cast<bool>(random_number);
                rT_W[hmap_keyword_trapdoor]->setServerID(random_bit);
            }
            lstKey.push_back(hmap_keyword_trapdoor);
            // Clearing contents
            word.clear();
        }
    }
exit:
    delete dsse_trapdoor;
    return ret;
}

int DSSE::precomputeAES_CTR_keys(TYPE_INDEX* col_idx_arr, TYPE_INDEX* row_idx_arr, int serverID,
                                TYPE_COUNTER* col_counter_arr, TYPE_COUNTER* row_counter_arr, 
                                unsigned char* key_search_decrypt, unsigned char* key_update_decrypt, 
                                unsigned char* key_search_reencrypt[NUM_IDX_PER_DIM], unsigned char* key_update_reencrypt[NUM_IDX_PER_DIM],
                                MasterKey* pKey)
{
    TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX::iterator it;
    
    unsigned char U[BLOCK_CIPHER_SIZE];
    unsigned char V[BLOCK_CIPHER_SIZE];
    unsigned char uchar_counter[BLOCK_CIPHER_SIZE];
    unsigned char row_key[BLOCK_CIPHER_SIZE];
    int ret;
    DSSE_KeyGen* dsse_keygen = new DSSE_KeyGen();
    TYPE_INDEX row,col;
    TYPE_INDEX idx;
    TYPE_INDEX index;
    int bit_position;
    TYPE_INDEX row_empty, col_empty, size;

    
    //auto start = time_now;
    //auto end = time_now;
    //auto start_total = time_now;
    //auto end_total = time_now;
    double time_aeskey = 0;
    double total_time= 0;
    memset(U,0,BLOCK_CIPHER_SIZE);
    /* Decrypt key */
    //update key
    col = col_idx_arr[1]; // 1 is non-empty address
    for(index = 0 , size =Client_DSSE::lstT_W_IDX[serverID].size() ;  index < size; index++)
    {
        //row =  strtoul(it->first.c_str(),NULL,0);
        row = Client_DSSE::lstT_W_IDX[serverID][index];
        
        
        //memset(uchar_counter,0,BLOCK_CIPHER_SIZE);
        memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&col_counter_arr[col],sizeof(TYPE_COUNTER));
        memcpy(&uchar_counter,&col,sizeof(TYPE_INDEX));
        //start = time_now;
        // AES CTR 128 function
        aes128_ctr_encdec(U, V, &Client_DSSE::precomputed_row_key[serverID][row*BLOCK_CIPHER_SIZE], uchar_counter, ONE_VALUE);            
        //end = time_now;
        //time_aeskey = time_aeskey + std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count();
            
        idx = row / BYTE_SIZE;
        bit_position = row % BYTE_SIZE;
        
        
        if(BIT_CHECK(&V[0],0))
            BIT_SET(&key_update_decrypt[idx],bit_position);
        else
            BIT_CLEAR(&key_update_decrypt[idx],bit_position);
    }   
    //search key
    row = row_idx_arr[1];
    for(index = 0, size =Client_DSSE::lstT_F_IDX[serverID].size() ; index < size;index++)
    {
        //col =  strtoul(it->first.c_str(),NULL,0);
        col = Client_DSSE::lstT_F_IDX[serverID][index];
        
        //memset(uchar_counter,0,BLOCK_CIPHER_SIZE);
        memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&col_counter_arr[col],sizeof(col_counter_arr[col]));
        memcpy(&uchar_counter,&col,sizeof(TYPE_INDEX));
        
        //start = time_now;
        // AES CTR 128 function
        aes128_ctr_encdec(U, V, &Client_DSSE::precomputed_row_key[serverID][row*BLOCK_CIPHER_SIZE], uchar_counter, ONE_VALUE);
        
        //end = time_now;
        //time_aeskey = time_aeskey + std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count();
        
        //key->lstKey_search_decrypt[k].push_back(V[0]);
        idx = col / BYTE_SIZE;
        bit_position = col % BYTE_SIZE;
        
        if(BIT_CHECK(&V[0],0))
            BIT_SET(&key_search_decrypt[idx],bit_position);
        else
            BIT_CLEAR(&key_search_decrypt[idx],bit_position);
    }
        
    //Re-encryption key , ( remember to increase counters to 1)
    col = col_idx_arr[1];
    col_counter_arr[col]++;
    col_empty = col_idx_arr[0];
    col_counter_arr[col_empty]++;
    row = row_idx_arr[1];
    row_counter_arr[row]++;
    row_empty = row_idx_arr[0];
    row_counter_arr[row_empty]++;
    
    /* 
     * Update the list of index - not important, this is just to measure the online performance
     * */
        
    //add the non-empty row temporarily
    
    Client_DSSE::lstT_W_IDX[serverID].push_back(row_empty);
    
    // update precomputed row keys
    this->updateRow_key(row_counter_arr,serverID,row,Client_DSSE::precomputed_row_key[serverID],pKey);
    this->updateRow_key(row_counter_arr,serverID,row_empty,Client_DSSE::precomputed_row_key[serverID],pKey);
        
    
    for(index = 0 ,size =Client_DSSE::lstT_W_IDX[serverID].size()  ;  index < size; index++)
    {
        row = Client_DSSE::lstT_W_IDX[serverID][index];
    
        //memset(uchar_counter,0,BLOCK_CIPHER_SIZE);
        memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&col_counter_arr[col],sizeof(col_counter_arr[col]));
        memcpy(&uchar_counter,&col,sizeof(TYPE_INDEX));
        //start = time_now;
        // AES CTR 128 function
        aes128_ctr_encdec(U, V, &Client_DSSE::precomputed_row_key[serverID][row*BLOCK_CIPHER_SIZE], uchar_counter, ONE_VALUE);
        //end = time_now;
        
        //time_aeskey = time_aeskey + std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count();
            
        idx = row / BYTE_SIZE;
        bit_position = row % BYTE_SIZE;
        if(BIT_CHECK(&V[0],0))
            BIT_SET(&key_update_reencrypt[0][idx],bit_position);
        else
            BIT_CLEAR(&key_update_reencrypt[0][idx],bit_position);
    
        memset(U,0,1);
            
        memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&col_counter_arr[col_empty],sizeof(col_counter_arr[col_empty]));
        memcpy(&uchar_counter,&col_empty,sizeof(TYPE_INDEX));
        // AES CTR 128 function
        
        aes128_ctr_encdec(U, V, &Client_DSSE::precomputed_row_key[serverID][row*BLOCK_CIPHER_SIZE], uchar_counter, ONE_VALUE);
        
        if(BIT_CHECK(&V[0],0))
            BIT_SET(&key_update_reencrypt[1][idx],bit_position);
        else
            BIT_CLEAR(&key_update_reencrypt[1][idx],bit_position);
    }
    //remove the added temporary row
       
    Client_DSSE::lstT_W_IDX[serverID].pop_back();
    
    // search key
    row = row_idx_arr[1];
    row_empty = row_idx_arr[0];
    
    
    //add the empty col temporarily
    Client_DSSE::lstT_F_IDX[serverID].push_back(col_empty);
         
    for(index = 0, size =Client_DSSE::lstT_F_IDX[serverID].size() ; index < size;index++)
    {
        //col =  strtoul(it->first.c_str(),NULL,0);
        col = Client_DSSE::lstT_F_IDX[serverID][index];
        
        //memset(uchar_counter,0,BLOCK_CIPHER_SIZE);
        memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&col_counter_arr[col],sizeof(col_counter_arr[col]));
        memcpy(&uchar_counter,&col,sizeof(TYPE_INDEX));
            
        //start = time_now;
        // AES CTR 128 function
        aes128_ctr_encdec(U, V, &Client_DSSE::precomputed_row_key[serverID][row*BLOCK_CIPHER_SIZE], uchar_counter, ONE_VALUE);
        
        //end = time_now;
        //time_aeskey = time_aeskey + std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count();
        
        idx = col / BYTE_SIZE;
        bit_position = col % BYTE_SIZE;
        if(BIT_CHECK(&V[0],0))
            BIT_SET(&key_search_reencrypt[0][idx],bit_position);
        else
            BIT_CLEAR(&key_search_reencrypt[0][idx],bit_position);
        
        //for empty address
            
        //memset(uchar_counter,0,BLOCK_CIPHER_SIZE);
        memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&col_counter_arr[col],sizeof(col_counter_arr[col]));
        memcpy(&uchar_counter,&col,sizeof(TYPE_INDEX));
        // AES CTR 128 function
        
        //start = time_now;
        aes128_ctr_encdec(U, V, &Client_DSSE::precomputed_row_key[serverID][row_empty*BLOCK_CIPHER_SIZE], uchar_counter, ONE_VALUE);
            
        
        //end = time_now;
        //time_aeskey = time_aeskey + std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count();
        
        if(BIT_CHECK(&V[0],0))
            BIT_SET(&key_search_reencrypt[1][idx],bit_position);
        else
            BIT_CLEAR(&key_search_reencrypt[1][idx],bit_position);
    
    }
    //remove the temporary  col
    Client_DSSE::lstT_F_IDX[serverID].pop_back();
    
    //end_total = time_now;
exit:
    //time_aeskey = time_aeskey / 1000000.0;
    //printf("Total time for aes key: %8.4f ms\n",time_aeskey);
    //total_time = std::chrono::duration_cast<std::chrono::nanoseconds>(end_total-start_total).count()/1000000.0;
    //printf("Total time for precomputation key: %8.4f ms\n",total_time);
    
    return ret;
}

int DSSE::precomputeAES_CTR_keys_decrypt(TYPE_INDEX* idx_arr, int serverID, int op,
                                TYPE_COUNTER* col_counter_arr, 
                                unsigned char* key_decrypt,
                                MasterKey* pKey)
{
    TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX::iterator it;
    
    unsigned char U[BLOCK_CIPHER_SIZE];
    unsigned char V[BLOCK_CIPHER_SIZE];
    unsigned char uchar_counter[BLOCK_CIPHER_SIZE];
    unsigned char row_key[BLOCK_CIPHER_SIZE];
    int ret;
    DSSE_KeyGen* dsse_keygen = new DSSE_KeyGen();
    TYPE_INDEX row,col;
    TYPE_INDEX idx;
    TYPE_INDEX index;
    int bit_position;
    TYPE_INDEX row_empty, col_empty, size;

    
    //auto start = time_now;
    //auto end = time_now;
    //auto start_total = time_now;
    //auto end_total = time_now;
    double time_aeskey = 0;
    double total_time= 0;
    memset(U,0,BLOCK_CIPHER_SIZE);
    /* Decrypt key */
    if(op == UPDATE_OPERATION)
    {
        
        //update key
        col = idx_arr[1]; // 1 is non-empty address
        for(index = 0 , size =Client_DSSE::lstT_W_IDX[serverID].size() ;  index < size; index++)
        {
            row = Client_DSSE::lstT_W_IDX[serverID][index];
            
            
            memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&col_counter_arr[col],sizeof(TYPE_COUNTER));
            memcpy(&uchar_counter,&col,sizeof(TYPE_INDEX));
            
            // AES CTR 128 function
            aes128_ctr_encdec(U, V, &Client_DSSE::precomputed_row_key[serverID][row*BLOCK_CIPHER_SIZE], uchar_counter, ONE_VALUE);                
            idx = row / BYTE_SIZE;
            bit_position = row % BYTE_SIZE;
            
            
            if(BIT_CHECK(&V[0],0))
                BIT_SET(&key_decrypt[idx],bit_position);
            else
                BIT_CLEAR(&key_decrypt[idx],bit_position);
        }   
    }
    else
    {
        //search key
        row = idx_arr[1];
        for(index = 0, size =Client_DSSE::lstT_F_IDX[serverID].size() ; index < size;index++)
        {
            col = Client_DSSE::lstT_F_IDX[serverID][index];
            
            memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&col_counter_arr[col],sizeof(col_counter_arr[col]));
            memcpy(&uchar_counter,&col,sizeof(TYPE_INDEX));
            
            // AES CTR 128 function
            aes128_ctr_encdec(U, V, &Client_DSSE::precomputed_row_key[serverID][row*BLOCK_CIPHER_SIZE], uchar_counter, ONE_VALUE);
            
            idx = col / BYTE_SIZE;
            bit_position = col % BYTE_SIZE;
            
            if(BIT_CHECK(&V[0],0))
                BIT_SET(&key_decrypt[idx],bit_position);
            else
                BIT_CLEAR(&key_decrypt[idx],bit_position);
        }
    }
    //end_total = time_now;
exit:
    //total_time = std::chrono::duration_cast<std::chrono::nanoseconds>(end_total-start_total).count()/1000000.0;
    //printf("Total time for precomputation key: %8.4f ms\n",total_time);
    
    return ret;
}
int DSSE::precomputeAES_CTR_keys_reencrypt(TYPE_INDEX* col_idx_arr, TYPE_INDEX* row_idx_arr, int serverID, int op,
                                TYPE_COUNTER* col_counter_arr, TYPE_COUNTER* row_counter_arr, 
                                unsigned char* key_reencrypt,
                                MasterKey* pKey)
{
    TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX::iterator it;
    
    unsigned char U[BLOCK_CIPHER_SIZE];
    unsigned char V[BLOCK_CIPHER_SIZE];
    unsigned char uchar_counter[BLOCK_CIPHER_SIZE];
    unsigned char row_key[BLOCK_CIPHER_SIZE];
    int ret;
    DSSE_KeyGen* dsse_keygen = new DSSE_KeyGen();
    TYPE_INDEX row,col;
    TYPE_INDEX idx;
    TYPE_INDEX index;
    int bit_position;
    TYPE_INDEX row_empty, col_empty, size;
    
    TYPE_COUNTER row_new_ctr[NUM_IDX_PER_DIM];
    TYPE_COUNTER col_new_ctr[NUM_IDX_PER_DIM];
    unsigned char new_row_key[NUM_IDX_PER_DIM][BLOCK_CIPHER_SIZE];
    unsigned char new_row_key_input [BLOCK_CIPHER_SIZE];
    //auto start = time_now;
    //auto end = time_now;
    //auto start_total = time_now;
    //auto end_total = time_now;
    double time_aeskey = 0;
    double total_time= 0;
    memset(U,0,BLOCK_CIPHER_SIZE);
    
    for(int i = 0 ; i <NUM_IDX_PER_DIM;i++)
    {
        row_new_ctr[i]=row_counter_arr[row_idx_arr[i]]+1;
        col_new_ctr[i]= col_counter_arr[col_idx_arr[i]]+1;
        
    }
    //regenerate new row key

    for(int i = 0 ;i <NUM_IDX_PER_DIM; i++)
    {
        memset(new_row_key[i],0,BLOCK_CIPHER_SIZE);
        memset(new_row_key_input,0,BLOCK_CIPHER_SIZE);
        memcpy(new_row_key_input,&row_idx_arr[i],sizeof(TYPE_INDEX));
        memcpy(&new_row_key_input[BLOCK_CIPHER_SIZE/2],&row_new_ctr[i],sizeof(row_new_ctr[i]));
        dsse_keygen->genRow_key(new_row_key[i], BLOCK_CIPHER_SIZE, new_row_key_input, BLOCK_CIPHER_SIZE, serverID, pKey);
    }
    
    
    
    // update precomputed row keys --remember to regenerate this after finishing all precomputation threads
    /*
    this->updateRow_key(row_counter_arr,serverID,row,Client_DSSE::precomputed_row_key[serverID],pKey);
    this->updateRow_key(row_counter_arr,serverID,row_empty,Client_DSSE::precomputed_row_key[serverID],pKey);
    */
  
    if(op == UPDATE_OPERATION)
    {
        col = col_idx_arr[1];
        col_empty = col_idx_arr[0];
        for(index = 0 ,size =Client_DSSE::lstT_W_IDX[serverID].size()  ;  index < size; index++)
        {
            
            row = Client_DSSE::lstT_W_IDX[serverID][index];
            
            memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&col_new_ctr[1],sizeof(col_new_ctr[1]));
            memcpy(&uchar_counter,&col,sizeof(TYPE_INDEX));
            // AES CTR 128 function
            aes128_ctr_encdec(U, V, &Client_DSSE::precomputed_row_key[serverID][row*BLOCK_CIPHER_SIZE], uchar_counter, ONE_VALUE);
                
            idx = row / BYTE_SIZE;
            bit_position = row % BYTE_SIZE;
            if(BIT_CHECK(&V[0],0))
                BIT_SET(&key_reencrypt[idx],bit_position);
            else
                BIT_CLEAR(&key_reencrypt[idx],bit_position);
        
            memset(U,0,1);
                
            memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&col_new_ctr[0],sizeof(col_new_ctr[0]));
            memcpy(&uchar_counter,&col_empty,sizeof(TYPE_INDEX));
            // AES CTR 128 function
            
            aes128_ctr_encdec(U, V, &Client_DSSE::precomputed_row_key[serverID][row*BLOCK_CIPHER_SIZE], uchar_counter, ONE_VALUE);
            
            if(BIT_CHECK(&V[0],0))
                BIT_SET(&key_reencrypt[(MATRIX_ROW_SIZE/BYTE_SIZE)+idx],bit_position);
            else
                BIT_CLEAR(&key_reencrypt[(MATRIX_ROW_SIZE/BYTE_SIZE)+idx],bit_position);
        }
        //generate keys for such updated row keys   
        for(int i = 0 ; i <NUM_IDX_PER_DIM;i++)
        {
            row = row_idx_arr[i];
            
            memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&col_new_ctr[1],sizeof(col_new_ctr[1]));
            memcpy(&uchar_counter,&col,sizeof(TYPE_INDEX));
            // AES CTR 128 function
            aes128_ctr_encdec(U, V, new_row_key[i], uchar_counter, ONE_VALUE);
                
            idx = row / BYTE_SIZE;
            bit_position = row % BYTE_SIZE;
            if(BIT_CHECK(&V[0],0))
                BIT_SET(&key_reencrypt[idx],bit_position);
            else
                BIT_CLEAR(&key_reencrypt[idx],bit_position);
        
            memset(U,0,1);
                
            memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&col_new_ctr[0],sizeof(col_new_ctr[0]));
            memcpy(&uchar_counter,&col_empty,sizeof(TYPE_INDEX));
            // AES CTR 128 function
            
            aes128_ctr_encdec(U, V, new_row_key[i], uchar_counter, ONE_VALUE);
            
            if(BIT_CHECK(&V[0],0))
                BIT_SET(&key_reencrypt[(MATRIX_ROW_SIZE/BYTE_SIZE)+idx],bit_position);
            else
                BIT_CLEAR(&key_reencrypt[(MATRIX_ROW_SIZE/BYTE_SIZE)+idx],bit_position);
        }
    }
    else
    {
        // search key
        row = row_idx_arr[1];
        row_empty = row_idx_arr[0];
        
        for(index = 0, size =Client_DSSE::lstT_F_IDX[serverID].size() ; index < size;index++)
        {
            col = Client_DSSE::lstT_F_IDX[serverID][index];
            
            memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&col_counter_arr[col],sizeof(col_counter_arr[col]));
            memcpy(&uchar_counter,&col,sizeof(TYPE_INDEX));
                
            // AES CTR 128 function
            aes128_ctr_encdec(U, V, new_row_key[1], uchar_counter, ONE_VALUE);
            
            idx = col / BYTE_SIZE;
            bit_position = col % BYTE_SIZE;
            if(BIT_CHECK(&V[0],0))
                BIT_SET(&key_reencrypt[idx],bit_position);
            else
                BIT_CLEAR(&key_reencrypt[idx],bit_position);
            
            //for empty address
                
            memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&col_counter_arr[col],sizeof(col_counter_arr[col]));
            memcpy(&uchar_counter,&col,sizeof(TYPE_INDEX));
            // AES CTR 128 function
            
            aes128_ctr_encdec(U, V, new_row_key[0], uchar_counter, ONE_VALUE);
                
            if(BIT_CHECK(&V[0],0))
                BIT_SET(&key_reencrypt[MATRIX_COL_SIZE+idx],bit_position);
            else
                BIT_CLEAR(&key_reencrypt[MATRIX_COL_SIZE+idx],bit_position);
        }
        //generate aes keys for such updated columns
        for(int i = 0 ; i < NUM_IDX_PER_DIM;i++)
        {
            col = col_idx_arr[i];
            
            memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&col_new_ctr[i],sizeof(col_new_ctr[i]));
            memcpy(&uchar_counter,&col,sizeof(TYPE_INDEX));
                
            // AES CTR 128 function
            aes128_ctr_encdec(U, V, new_row_key[1], uchar_counter, ONE_VALUE);
            
            idx = col / BYTE_SIZE;
            bit_position = col % BYTE_SIZE;
            if(BIT_CHECK(&V[0],0))
                BIT_SET(&key_reencrypt[idx],bit_position);
            else
                BIT_CLEAR(&key_reencrypt[idx],bit_position);
            
            //for empty address
                
            memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&col_new_ctr[i],sizeof(col_new_ctr[i]));
            memcpy(&uchar_counter,&col,sizeof(TYPE_INDEX));
            // AES CTR 128 function
            
            aes128_ctr_encdec(U, V, new_row_key[0], uchar_counter, ONE_VALUE);
                
            if(BIT_CHECK(&V[0],0))
                BIT_SET(&key_reencrypt[MATRIX_COL_SIZE+idx],bit_position);
            else
                BIT_CLEAR(&key_reencrypt[MATRIX_COL_SIZE+idx],bit_position);
        }
    }
    
    //end_total = time_now;
exit:
    //time_aeskey = time_aeskey / 1000000.0;
    //printf("Total time for aes key: %8.4f ms\n",time_aeskey);
    //total_time = std::chrono::duration_cast<std::chrono::nanoseconds>(end_total-start_total).count()/1000000.0;
    //printf("Total time for precomputation key: %8.4f ms\n",total_time);
    
    return ret;
}
int DSSE::enc_decBlock_with_preAESKey(MatrixType *I, int op, //input 
                        unsigned char preKey[],
                        MatrixType *I_prime)
{
    int ret;
    unsigned char U;
    unsigned char V;
    TYPE_INDEX col;
    int bit_number;
    TYPE_INDEX idx;
    TYPE_INDEX size;
    TYPE_GOOGLE_DENSE_HASH_MAP_FOR_INDEX::iterator it;
    idx = 0;
    auto start = time_now;
    if(op == ROW_DATA)
        size = MATRIX_COL_SIZE;
    else
        size = MATRIX_ROW_SIZE / BYTE_SIZE;
    for(col = 0 ; col<size;col++)
    {
        I_prime[col].byte_data = I[col].byte_data ^ preKey[col];
    }
exit:
    return ret;
}

int DSSE::precomputeRow_keys(   TYPE_COUNTER* row_counter_arr[NUM_SERVERS],
                                unsigned char output[NUM_SERVERS][MATRIX_ROW_SIZE*BLOCK_CIPHER_SIZE],
                                MasterKey *pKey)
{
    TYPE_INDEX row;
    unsigned char row_key [BLOCK_CIPHER_SIZE];
    unsigned char row_key_input [BLOCK_CIPHER_SIZE];
    int ret;
    DSSE_KeyGen* dsse_keygen = new DSSE_KeyGen();
    for ( int k = 0 ; k < NUM_SERVERS; k++)
    {
        memset(output[k],0,BLOCK_CIPHER_SIZE*MATRIX_ROW_SIZE);
        for(row = 0 ; row < MATRIX_ROW_SIZE ; row++)
        {
            memset(row_key,0,sizeof(row_key));
            memset(row_key_input,0,sizeof(row_key_input));
            memcpy(row_key_input,&row,sizeof(row));
            memcpy(&row_key_input[BLOCK_CIPHER_SIZE/2],&row_counter_arr[k][row],sizeof(row_counter_arr[k][row]));
            if((ret = dsse_keygen->genRow_key(row_key, BLOCK_CIPHER_SIZE, row_key_input, BLOCK_CIPHER_SIZE, k, pKey))!=0)
            {
                goto exit;
            }
            
            memcpy(&output[k][row*BLOCK_CIPHER_SIZE],row_key,BLOCK_CIPHER_SIZE);
        }
    }
exit:
    memset(row_key,0,BLOCK_CIPHER_SIZE);
    memset(row_key_input,0,BLOCK_CIPHER_SIZE);
    delete dsse_keygen;
    return ret;
}
int DSSE::updateRow_key(TYPE_COUNTER* row_counter_arr, int serverID, TYPE_INDEX updateIdx,
                                unsigned char output[MATRIX_ROW_SIZE*BLOCK_CIPHER_SIZE],
                                MasterKey *pKey)
{
    DSSE_KeyGen* dsse_keygen = new DSSE_KeyGen();
    unsigned char row_key [BLOCK_CIPHER_SIZE];
    unsigned char row_key_input [BLOCK_CIPHER_SIZE];
    int ret;
    memset(row_key,0,sizeof(row_key));
    memset(row_key_input,0,sizeof(row_key_input));
    memcpy(row_key_input,&updateIdx,sizeof(updateIdx));
    memcpy(&row_key_input[BLOCK_CIPHER_SIZE/2],&row_counter_arr[updateIdx],sizeof(row_counter_arr[updateIdx]));
    if((ret = dsse_keygen->genRow_key(row_key, BLOCK_CIPHER_SIZE, row_key_input, BLOCK_CIPHER_SIZE, serverID, pKey))!=0)
    {
        goto exit;
    }
    memcpy(&output[updateIdx*BLOCK_CIPHER_SIZE],row_key,BLOCK_CIPHER_SIZE);
exit:
    memset(row_key,0,BLOCK_CIPHER_SIZE);
    memset(row_key_input,0,BLOCK_CIPHER_SIZE);
    delete dsse_keygen;
    return ret;
}


int DSSE::loadWhole_encrypted_matrix_from_file(MatrixType** I_big, int serverID)
{
    int n; 
    TYPE_INDEX col, row, I_big_col_idx;
    Miscellaneous misc;
    n = MATRIX_COL_SIZE/MATRIX_PIECE_COL_SIZE;
    MatrixType **I = new MatrixType*[MATRIX_ROW_SIZE];
    for(TYPE_INDEX m = 0 ; m < MATRIX_ROW_SIZE; m++)
    {
        I[m] = new MatrixType[MATRIX_PIECE_COL_SIZE];
    }
    for(int i = 0 ; i < n ; i++)
    {
        for(TYPE_INDEX m = 0 ; m < MATRIX_ROW_SIZE; m++)
        {
            memset(I[m],0,MATRIX_PIECE_COL_SIZE);
        }
        string filename = std::to_string(serverID)+ "-" +  std::to_string(i);
        misc.read_matrix_from_file(filename,gcsMatrixPiece,I,MATRIX_ROW_SIZE,MATRIX_PIECE_COL_SIZE);
        //for(curIdx  = MATRIX_PIECE_COL_SIZE*i; curIdx < MATRIX_PIECE_COL_SIZE * (i+1); curIdx++)
        for(col = 0; col < MATRIX_PIECE_COL_SIZE; col++)
        {
            I_big_col_idx = col+ (i*MATRIX_PIECE_COL_SIZE);
            for(row = 0 ; row < MATRIX_ROW_SIZE ; row++)
            {
                I_big[row][I_big_col_idx].byte_data = I[row][col].byte_data;
            }
        }
    }
    for(TYPE_INDEX m = 0 ; m < MATRIX_ROW_SIZE; m++)
    {
        delete I[m];
    }
    delete I;
}
int DSSE::scanDatabase(
		vector<string> &rFileNames,
		TYPE_KEYWORD_DICTIONARY &rKeywordsDictionary,
        string path)
{

	int keyword_len = 0;
	unsigned char keyword_trapdoor[TRAPDOOR_SIZE], file_trapdoor[TRAPDOOR_SIZE];
	string word;
	DIR *pDir;
	struct dirent *pEntry;
	struct stat file_stat;
	string file_name, file_name_with_path;
	TYPE_KEYWORD_DICTIONARY words_per_file;
	set<string>::iterator iter;

	try{
		if((pDir=opendir(path.c_str())) != NULL){
			while((pEntry = readdir(pDir))!=NULL){

				file_name = pEntry->d_name;

				if(!file_name.compare(".") || !file_name.compare("..")) {
					continue;
				}
				else{

					file_name_with_path = path + pEntry->d_name;                                      // "/" +

					// If the file is a directory (or is in some way invalid) we'll skip it
					if (stat(file_name_with_path.c_str(), &file_stat)) continue;

					if (S_ISDIR(file_stat.st_mode))
                    {
						file_name_with_path.append("/");
                        scanDatabase(rFileNames, rKeywordsDictionary, file_name_with_path);
						continue;
					}

					rFileNames.push_back(file_name_with_path.c_str());
            
                    KeywordExtraction* wordext = new KeywordExtraction(); 
					wordext->extractKeywords(words_per_file, file_name, path);

					for(iter=words_per_file.begin();iter != words_per_file.end();iter++) 
                    {
                        word = *iter;
						keyword_len = word.size();
						if(keyword_len>0)
                        {
                            rKeywordsDictionary.insert(word);
                        }
						else
							continue;                        
                        // Clearing contents
						word.clear();
					}
					// Clearing contents
					words_per_file.clear();
					file_name_with_path.clear();
				}
				// Clearing contents
				file_name.clear();
			}

			closedir(pDir);
		}

		else{
			cout << "Could not locate the directory..." << endl;
		}
	}catch(exception &e){
		cout << "Error occurred in generate_file_trapdoors function " << e.what() << endl;
	}

	return 0;
}
int DSSE::createEncryptedMatrix_from_kw_file_pair(TYPE_COUNTER* col_counter_arr[NUM_SERVERS]) //col_size MUST be a mutiple of BYTE_SIZE
{
    int n; 
    TYPE_INDEX curIdx;
    TYPE_INDEX size_row;
    TYPE_INDEX col, row, row_idx;
    TYPE_INDEX vector_idx = 0;

    int bit_number;
    Miscellaneous misc;
    n = MATRIX_COL_SIZE/MATRIX_PIECE_COL_SIZE;
    int error;
    int seed_len = (BLOCK_CIPHER_SIZE*2) ; //create send of length 256 bit appropriate with AES and SHA-256
    unsigned char* random_string = new unsigned char[MATRIX_ROW_SIZE*MATRIX_PIECE_COL_SIZE];
    unsigned char* pSeed ;
    
    unsigned char U[BLOCK_CIPHER_SIZE];
    unsigned char V[BLOCK_CIPHER_SIZE];
    unsigned char uchar_counter[BLOCK_CIPHER_SIZE];
    DSSE_KeyGen* dsse_keygen = new DSSE_KeyGen();
    MatrixType** I = new MatrixType*[MATRIX_ROW_SIZE];
    for(TYPE_INDEX m = 0 ; m < MATRIX_ROW_SIZE; m++)
    {
        I[m] = new MatrixType[MATRIX_PIECE_COL_SIZE];
    }
    pSeed = new unsigned char[seed_len];
    for(int k = 0 ; k < NUM_SERVERS; k++)
    {
        for(TYPE_INDEX i = 0 ; i < n ; i++)
        {
            cout<<endl<<i<<"...."<<endl;
            auto start = time_now;
             //create a random matrix first
            memset(pSeed,0,seed_len);
            memset(random_string,0,MATRIX_ROW_SIZE*MATRIX_PIECE_COL_SIZE);
            
            if ((error = dsse_keygen->rdrand(pSeed,seed_len, RDRAND_RETRY_NUM)) != CRYPT_OK) 
            {
                printf("Error calling rdrand_get_n_units_retry: %d\n", error/*error_to_string(error)*/);
            }
             if ((error = dsse_keygen->invokeFortuna_prng(pSeed, random_string, seed_len, MATRIX_ROW_SIZE*MATRIX_PIECE_COL_SIZE)) != CRYPT_OK) {
                printf("Error calling call_fortuna_prng function: %d\n", error/*error_to_string(error)*/);
            }
            
            curIdx = 0;
            for(TYPE_INDEX m = 0 ; m < MATRIX_ROW_SIZE; m++)
            {
                memcpy(I[m],&random_string[curIdx],MATRIX_PIECE_COL_SIZE);
                curIdx += MATRIX_PIECE_COL_SIZE;
            }
            for(curIdx  = MATRIX_PIECE_COL_SIZE*i,col=0; curIdx < MATRIX_PIECE_COL_SIZE * (i+1); col++,curIdx++)
            {
                for(bit_number = 0 ; bit_number < BYTE_SIZE; bit_number++)
                {
                    vector_idx = curIdx * BYTE_SIZE + bit_number;
                    for(row = 0, size_row= Client_DSSE::lstT_W_IDX[k].size(); row < size_row; row++)
                    {
                        row_idx = Client_DSSE::lstT_W_IDX[k][row];
                        BIT_CLEAR(&I[row_idx][col].byte_data,bit_number);
                    }
                    for(row = 0, size_row = Client_DSSE::kw_file_pair[k][vector_idx].size(); row < size_row; row++)
                    {
                        row_idx = Client_DSSE::kw_file_pair[k][vector_idx][row];
                        BIT_SET(&I[row_idx][col].byte_data,bit_number);
                    }
                    for(row = 0, size_row= Client_DSSE::lstT_W_IDX[k].size(); row < size_row; row++)
                    {
                        row_idx = Client_DSSE::lstT_W_IDX[k][row];
                        memset(U,0,1);
                        if(BIT_CHECK(&I[row_idx][col].byte_data,bit_number))
                            BIT_SET(&U[0],0);
                            
                        memset(uchar_counter,0,BLOCK_CIPHER_SIZE);
                        memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&col_counter_arr[k][vector_idx],sizeof(TYPE_COUNTER));
                        memcpy(&uchar_counter,&vector_idx,sizeof(TYPE_INDEX));
                        // Encrypting the  matrix I using AES CTR 128 function
                        aes128_ctr_encdec(U, V, &Client_DSSE::precomputed_row_key[k][row_idx*BLOCK_CIPHER_SIZE], uchar_counter, ONE_VALUE);
                        // Write the encryped row back to matrix I
                        if(BIT_CHECK(&V[0],0))
                            BIT_SET(&I[row_idx][col].byte_data,bit_number);
                        else
                            BIT_CLEAR(&I[row_idx][col].byte_data,bit_number);           
                    }
                }
            }
            //write the matrix to file
            string filename = std::to_string(k) + "-"+ std::to_string(i);
            misc.write_matrix_to_file(filename,gcsMatrixPiece,I,MATRIX_ROW_SIZE,MATRIX_PIECE_COL_SIZE);
            
            auto end = time_now;
            cout<<"time: "<<std::chrono::duration_cast<std::chrono::seconds>(end-start).count()<<"s"<<endl;
        }
    }
exit:
    for(TYPE_INDEX m = 0 ; m < MATRIX_ROW_SIZE; m++)
    {
        delete I[m];
    }
    delete I;
            
    delete random_string;
    delete dsse_keygen;
}
