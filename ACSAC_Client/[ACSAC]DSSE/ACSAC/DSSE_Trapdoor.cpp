#include "DSSE_Trapdoor.h"
#include "tomcrypt_cpp.h"
#include "Miscellaneous.h"
#include "Keyword_Extraction.h"
DSSE_Trapdoor::DSSE_Trapdoor()
{
}

DSSE_Trapdoor::~DSSE_Trapdoor()
{
}

int DSSE_Trapdoor::generateTrapdoors(TYPE_GOOGLE_DENSE_HASH_MAP &rT_W,
		TYPE_GOOGLE_DENSE_HASH_MAP &rT_F,
		vector<string> &rFileNames,
		TYPE_KEYWORD_DICTIONARY &rKeywordsDictionary,
        TYPE_INDEX &max_row_idx,
        TYPE_INDEX &max_col_idx,
		string path,
		MasterKey *pKey)
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
					// if (S_ISDIR(file_stat.st_mode ))         continue;

					if (S_ISDIR(file_stat.st_mode)){
						file_name_with_path.append("/");

						generateTrapdoors(rT_W, rT_F, rFileNames, rKeywordsDictionary, max_row_idx, max_col_idx, file_name_with_path, pKey);
						continue;
					}

					rFileNames.push_back(file_name_with_path.c_str());

					if(file_name_with_path.size()>0)
						generateTrapdoor_single_input(file_trapdoor, TRAPDOOR_SIZE,	(unsigned char *)file_name_with_path.c_str(), file_name_with_path.size(), pKey);
					else
						cout << "File name is empty" << endl;

					hashmap_key_class hmap_file_trapdoor(file_trapdoor,TRAPDOOR_SIZE);
                    TYPE_INDEX file_idx = rT_F.bucket(hmap_file_trapdoor);
                    
                    if((file_idx ) >max_col_idx)
                        max_col_idx = file_idx;
                        
                    //rT_F[hmap_file_trapdoor] = ONE_VALUE;
                    
                    KeywordExtraction* wordext = new KeywordExtraction(); 
					wordext->extractKeywords(words_per_file, file_name, path);

					for(iter=words_per_file.begin();iter != words_per_file.end();iter++) {

						word = *iter;
						keyword_len = word.size();

						
						if(keyword_len>0)
                        {
                            rKeywordsDictionary.insert(word);
							this->generateTrapdoor_single_input(keyword_trapdoor, TRAPDOOR_SIZE, (unsigned char *)word.c_str(), keyword_len, pKey);
                        }
						else
							continue;

						hashmap_key_class hmap_keyword_trapdoor(keyword_trapdoor,TRAPDOOR_SIZE);
                        
                        
						
                        
                        TYPE_INDEX keyword_idx = rT_W.bucket(hmap_keyword_trapdoor);
                        //rT_W[hmap_keyword_trapdoor] = ONE_VALUE;
                        
                        if(keyword_idx > max_row_idx)
                        {
                            max_row_idx = keyword_idx;
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
			cout << "Could not locate the directory..." << endl;
		}
	}catch(exception &e){
		cout << "Error occurred in generate_file_trapdoors function " << e.what() << endl;
	}

	return 0;
}
/**
 * Generates trapdoor for input data
 *
 * @param pOutData			Trapdoor of the data computed is stored in it
 * @param out_len			Length of the trapdoor
 * @param pInData			Data as input that needs to be computed
 * @param in_len			Length of input data
 * @param pKey				Key for generating trapdoors
 * @return 0 if successful
 * Anvesh Ragi			10-02-2013		Function created
 */
int DSSE_Trapdoor::generateTrapdoor_single_input(unsigned char *pOutData,
		int out_len,
		unsigned char *pInData,
		int in_len,
		MasterKey *pKey) {

	// cout << "Entering data_trapdoor function" << endl;

	//cout << "key : ";
	//print_ucharstring(pKey->key2, TRAPDOOR_SIZE);

	// NULL checks
	if(pOutData == NULL || pInData == NULL || pKey->isNULL())
    {
        return -1;
    }
	
	if(out_len>0 && in_len>0)
		// Invoke OMAC which internally invokes AES CTR 128 mode for generating trapdoors
		omac_aes128_intel(pOutData, out_len, pInData, in_len, pKey->key2);
	//	hmac_sha256_intel(pKey->key2, pKey->skey2_3_pad_len, pInData, in_len, pOutData, out_len);
	else
		cout << "Either length of input or output to data_trapdoor is <= 0" << endl;
	// cout << "Exiting data_trapdoor function" << endl << endl;

	return 0;
}



