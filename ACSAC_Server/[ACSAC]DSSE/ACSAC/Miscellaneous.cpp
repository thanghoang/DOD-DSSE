#include "Miscellaneous.h"

#include "tomcrypt_cpp.h"
Miscellaneous::Miscellaneous()
{
}

Miscellaneous::~Miscellaneous()
{
}


/**
 * Function Name: print_ucharstring
 *
 * Description:
 * Prints an unsigned char pointer array in hex format
 *
 * @param pInput		Input
 * @param in_len 		Length of input
 * History
 * Name						Date					Comment
 * -----------------------------------------------------------------
 * Anvesh Ragi			10/02/2013				Function created
 */
 void Miscellaneous::print_ucharstring(const unsigned char *pInput,
                       int in_len){
	int indx;

	if(pInput != NULL && in_len>0){
		cout << "0x";
		for(indx=0;indx<in_len;indx++){
			if((indx%72==0)&&(indx!=0)){
				cout << "\n";
			}
			// cout << hex<< pInput[indx];
			printf("%.2x",pInput[indx]);
		}
	//	cout << "\n";
	}
	else{
		cout << "Input string is NULL" << endl;
	}
}

/**
 * Function Name: string_to_uchar
 *
 * Description:
 * Converts string type to unsigned char array type
 *
 * @param rDestination		Destination of type unsigned char array
 * @param source			Source of string type
 * @return 0 if successful
 * History
 * Name						Date				Comment
 * ------------------------------------------------------------------
 * Anvesh Ragi			11-05-2013			Function Created
 */
 int Miscellaneous::string_to_uchar(UCharArray &rDestination,
                    string source) {

	if(!source.empty() && rDestination.pUChar_array != NULL)
    {
		memcpy(rDestination.pUChar_array,(unsigned char *)source.c_str(),source.size());
	}
	else
    {
		cout << "Either source or destination is emtpy " << endl;
	}

	return 0;
}

/**
 * Function Name: ucarray_to_int
 *
 * Description:
 * Converts an unsigned char array to an integer type
 *
 * @param rDestination			Destination pointer (int)
 * @param pSource				Source pointer (unsigned char)
 * @param source_length			Length of the source
 * @return 0 if successful
 * History
 * Name					Date				Comment
 * -------------------------------------------------------------
 * Anvesh Ragi   	10-22-2013			Function Created
 */
 int Miscellaneous::ucarray_to_int(int &rDestination,
                   unsigned char *pSource,
                   int source_length){

	cout << "Entering ucarray_to_int function" << endl;

	int i = 0;

	if(source_length>=0){
		if(pSource !=NULL || source_length == 0){
			rDestination = pSource[0] << 8;
			for(i=1;i<source_length;i++){
				rDestination = rDestination | pSource[i] << 8;

			}
		}
		else{
			rDestination = 0;
		}
	}
	else{
		cout << "The length of source is <= zero" << endl;
	}

	cout << "Exiting ucarray_to_int function" << endl;

	return 0;
}

/**
 * Function Name: ucarray_to_ulong
 *
 * Description:
 * Converts an unsigned char array to a unsigned long (64-bit implementation) type
 *
 * @param rDestination			Destination pointer (unsigned long)
 * @param pSource				Source pointer (unsigned char)
 * @param source_length			Length of the source
 * @return 0 if successful
 * History
 * Name					Date				Comment
 * ------------------------------------------------------------------------------------
 * Anvesh Ragi   	10-22-2013			Function Created
 */
 int Miscellaneous::ucarray_to_ulong(unsigned long &rDestination,
                     unsigned char *pSource,
                     int source_length){

	cout << "Entering ucarray_to_long function" << endl;

	int i = 0;

	if(source_length>=0){
		if(pSource !=NULL || source_length == 0){
			rDestination = pSource[0] << 8;
			for(i=1;i<source_length;i++){
				rDestination = rDestination | pSource[i] << 8;

			}
		}
		else{
			rDestination = 0;
		}
	}
	else{
		cout << "The length of source is <= zero" << endl;
	}

	cout << "Exiting ucarray_to_long function" << endl;

	return 0;
}

/**
 * Function Name: longint_to_ucarray
 *
 * Description:
 * Converts a long int to an unsigned char array type
 *
 * @param pDestination			Destination pointer (unsigned char *)
 * @param destination_length	Length of the destination
 * @param pSource				Source pointer (long int)
 * @return 0 if successful
 * History
 * Name					Date				Comment
 * ---------------------------------------------------------------------
 * Anvesh Ragi   	10-28-2013			Function Created
 */
 int Miscellaneous::longint_to_ucarray(unsigned char *pDestination,
                       int destination_length,
                       TYPE_INDEX *pSource){

	int copy_num = sizeof(long int);
	if(pDestination != NULL && (long int)destination_length >= sizeof(long int)){
		memcpy(pDestination,pSource,copy_num);
	}
	else{
		cout << "The length of destination is <= long int size or destination pointer is not empty" << endl;
	}

	return 0;
}

/**
 * Function Name: prepare_initial_counter
 *
 * Description:
 * Prepares the initial counter used in AES encryption
 *
 * @param pInitialCounter				Pointer to the initial counter array
 * @param size							Size of the initial counter array
 * @param pSource						Source pointer (long int)
 * @return 0 if successful
 * History
 * Name						Date				Comment
 * ------------------------------------------------------------------------------
 * Anvesh Ragi 			10-28-2013			Function Created
 */
 int Miscellaneous::prepare_initial_counter(unsigned char *pInitialCounter,
                            int size,
                            TYPE_INDEX *pSource){

	int indx = 0;
	unsigned char tmp;
	if(pInitialCounter != NULL && size>0 && pSource != NULL){
		for(indx=0;indx < size;indx++)
			pInitialCounter[indx] = ZERO_VALUE;

		// Copy long int initial counter to unsigned char array at LSB
		longint_to_ucarray(pInitialCounter, size, pSource);

		for(indx = 0;indx<size/2;indx++) {
			tmp = pInitialCounter[indx];
			pInitialCounter[indx] = pInitialCounter[(size-1)-indx];
			pInitialCounter[(size-1)-indx] = tmp;
		}
	}else{
		cout << "Either source or destination pointer is NULL" << endl;
	}

	return 0;
}




/**
 * Function Name: print_file_names
 *
 * Description:
 * Prints the set of file names that needs to be processed
 *
 * @param file_names	Set of file names
 * @param size			Size of file names set
 * @return 0 if successful
 * History
 * Name						Date					Comment
 * ----------------------------------------------------------------
 * Anvesh Ragi			11-07-2013				Function Created
 */
 int Miscellaneous::print_file_names(string file_names[],
                     int size){
	int indx = 0;

	if(!file_names->empty()){
		for(indx = 0;indx < size; indx++){
			cout << file_names[indx] << endl;
		}
		cout << endl;
	}
	else{
		cout << "File names set is empty " <<endl;
	}

	return 0;
}

/**
 * Function Name: print_hash_map
 *
 * Description:
 * Prints the contents of a hash_map
 *
 * @param rHashMap			Hash map whose contents needs to be printed
 * @return 0 if successful
 * History
 * Name						Date						Comment
 * -----------------------------------------------------------------------
 * Anvesh Ragi			10-22-2013     				Function Created
 */
 /*
 int Miscellaneous::print_hash_map(TYPE_GOOGLE_DENSE_HASH_MAP &rHashMap){

	TYPE_COUNTER i = 0;
	hashmap_key_class hash_map_key;

	cout << "The contents of Hashmap are : " << endl;
	cout << "Number of entries in Hashmap are : " << rHashMap.bucket_count() << endl;
	if(!rHashMap.empty()){
		cout << "             Bucket size " << " Value " << "         Key "<< endl;
		cout << "             ------------" << " ----- " << "         ----" << endl;
		for(i=0;i<(TYPE_COUNTER)rHashMap.bucket_count();i++){
			hash_map_key = rHashMap.find_key_with_index(i);
			cout << "Bucket size for " << i << " : " << rHashMap.bucket_size(i) << "        ";
			cout << rHashMap.find_with_index(i) << "        " ;
			hash_map_key.print_data();
			cout << endl;
		}
		cout << endl;
	}
	else{
		cout << "Hash table is empty" << endl;
	}

	return 0;
}
 * */

/**
 * Function Name: print_matrix
 *
 * Description:
 * Prints the contents of matrix
 *
 * @param I				The matrix I that has to be printed
 * @return	0 if successful
 * History
 * Name						Date				Comment
 * -------------------------------------------------------------
 * Anvesh Ragi			10-25-2013  		Function created
 */
 int Miscellaneous::print_matrix(MatrixType **I){

	cout << "The contents of matrix I are : " << endl;

	int row = 0, col = 0;

	for(row=0;row<MATRIX_ROW_SIZE;row++) {

		cout << " Row " << row << " : ";

		for(col=0;col<MATRIX_COL_SIZE;col++){
			cout << bitset<BYTE_SIZE>(I[row][col].byte_data) << "       ";
		}
		cout <<endl;
	}
	cout << endl;

	return 0;
}

/**
 * Function Name: print_matrix_row
 *
 * Description:
 * Prints the contents of a row of matrix I
 *
 * @param I					The matrix I data structure
 * @param row				Row that needs to be printed
 * @return 0 if successful
 * History
 * Name							Date				Comment
 * -----------------------------------------------------------------
 * Anvesh Ragi				10-28-2013			Function Created
 */
 int Miscellaneous::print_matrix_row(MatrixType **I,
                     int row){
	cout << "The contents of matrix I for row " << row << " are : " << endl;

	int col = 0;

	for(col=0;col<MATRIX_COL_SIZE;col++){
		cout << bitset<BYTE_SIZE>(I[row][col].byte_data) << "       ";
	}
	cout <<endl;

	return 0;
}

/**
 * Function Name: print_matrix_column
 *
 * Description:
 * Prints the contents of a column of matrix I
 *
 * @param I					The matrix I data structure
 * @param col				Column that needs to be printed
 * @return 0 if successful
 * History
 * Name							Date				Comment
 * ----------------------------------------------------------------
 * Anvesh Ragi				10-28-2013			Function Created
 */
 int Miscellaneous::print_matrix_column(MatrixType **I,
                        int col){
	cout << "The contents of matrix I for column " << col << " are : " << endl;

	int row = 0;

	for(row=0;row<MATRIX_ROW_SIZE;row++){
		cout << "row " << row << " : " << bitset<BYTE_SIZE>(I[row][col].byte_data) << endl;
	}
	cout <<endl;

	return 0;
}


/**
 * Reads a file and returns the size of it
 *
 * @param file_name			Name of the file that should be read from
 * @return The size of the file
 * Anvesh Ragi			10/02/2013				Function created
 */
int Miscellaneous::read_filesize_cpp(string file_name){

	ifstream file_stream;
	int in_len = 0;

	file_stream.open(file_name.c_str(),ios::in);

	if (!file_stream.is_open()) {
		cout << stderr << "Can't open input file !\n";
		exit(1);
	}
	else{
		file_stream.seekg(0,std::ifstream::end);
		in_len = file_stream.tellg();
	}

	file_stream.close();

	return in_len;
}

/**
 * Reads data from a file and stores it in an unsigned char array
 *
 * @param pIndata		Data read from the file is stored in it
 * @param in_len 		The length of indata_ptr
 * @param file_name		Name of the file that should be read from
 * @return 0 if successful
 * Anvesh Ragi			10/02/2013				Function created
 */
int Miscellaneous::read_file_cpp(unsigned char *pInData,
		int in_len,
		string file_name) {

	ifstream file_stream;

	file_stream.open(file_name.c_str(),ios::in);

	// cout << "Reading from file " << file_name << " ... "<< endl;
	if (!file_stream.is_open()) {
		cout << stderr << "Can't open input file !\n";
		exit(1);
	}
	else{
		file_stream.read((char *)pInData,in_len);
	}

	file_stream.close();

	return 0;
}

/**
 * Reads data from an unsigned char array and writes it to a file
 *
 * @param file_name 	Name of the file into which data read from outdata_ptr is written
 * @param pOutdata 		Data is read from it
 * @param out_len 		The length of outdata_ptr
 * @return 0 if successful
 * Anvesh Ragi			10/02/2013				Function created
 */
int Miscellaneous::write_file_cpp(string file_name,
		unsigned char *pOutData,
		int out_len) {

	ofstream file_stream;

	file_stream.open(file_name.c_str(),ios::out | ios::trunc);

	if (!file_stream.is_open()) {
		cout << stderr << "Can't open output file !\n";
		exit(1);
	}
	else{
		file_stream.write((const char *)pOutData,out_len);
	}

	file_stream.close();

	return 0;
}

/**
 * Extracts the file names from a dataset location
 *
 * @param file_names			Set of file names which are extracted from a database location
 * @param pNumOfFiles			Number of files in database
 * @param rKeywordsDictionary	The keywords extracted from the file are stored in it
 * @param path              	Absolute path of database
 * @return 0 if successful
 * Anvesh Ragi			11-05-2013				Function Created
 */
int Miscellaneous::extract_file_names_with_path(vector<string> &rFileNames,
		string path){

	DIR *pDir;
	struct dirent *pEntry;
	struct stat file_stat;
	string file_name, file_name_with_path;

	try{
		if((pDir=opendir(path.c_str())) != NULL){
			while((pEntry = readdir(pDir))!=NULL){

				file_name = pEntry->d_name;

				if(!file_name.compare(".") || !file_name.compare("..")) {
					continue;
				}
				else{

					file_name_with_path = path + pEntry->d_name;

					if (stat(file_name_with_path.c_str(), &file_stat)) continue;

					if (S_ISDIR(file_stat.st_mode)){
						file_name_with_path.append("/");
						extract_file_names(rFileNames, file_name_with_path);
						continue;
					}


					rFileNames.push_back(file_name_with_path.c_str());
				}

				file_name.clear();
				file_name_with_path.clear();
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

int Miscellaneous::extract_file_names(vector<string> &rFileNames,
		string path){

	DIR *pDir;
	struct dirent *pEntry;
	string file_name, file_name_output;

	try{
		if((pDir=opendir(path.c_str())) != NULL){
			while((pEntry = readdir(pDir))!=NULL){

				file_name = pEntry->d_name;

				if(!file_name.compare(".") || !file_name.compare("..")) {
					continue;
				}
				else{
					rFileNames.push_back(file_name.c_str());
				}

				file_name.clear();
				file_name_output.clear();
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


int Miscellaneous::write_matrix_to_file(string filename, string path, MatrixType** I, TYPE_INDEX num_row, TYPE_INDEX num_col)
{
    std::ofstream output;
    FILE *foutput;
	TYPE_INDEX row;
	TYPE_INDEX col;
    stringstream filename_with_path;
    filename_with_path<<path<<filename;
    foutput = fopen(filename_with_path.str().c_str(),"wb+");
    
	for(row = 0; row < num_row; row++)
    {
		for(col = 0; col < num_col; col++)
        {
            fwrite(&I[row][col],1,1,foutput);
		}
	}
    fclose(foutput);
    return 0;
}
int Miscellaneous::read_matrix_from_file(string filename, string path, MatrixType** I, TYPE_INDEX num_row, TYPE_INDEX num_col)
{
    TYPE_INDEX row, col;
    FILE *finput;
    stringstream filename_with_path;
    filename_with_path << path << filename;
    finput = fopen(filename_with_path.str().c_str(), "rb" );
    for(row = 0 ; row < num_row;row++)
    {
        for(col = 0 ; col < num_col; col ++)
        {
            fread(&I[row][col],1,1,finput);
        }
    }
    fclose(finput);
    return 0;
}
int Miscellaneous::write_matrix_to_file(string filename, string path, bool** I, TYPE_INDEX num_row, TYPE_INDEX num_col)
{
    std::ofstream output;
	TYPE_INDEX row, col;

	output.open(path+filename);

	for(row = 0; row < num_row; row++)
    {
		for(col = 0; col < num_col; col++)
        {
            int tmp = I[row][col];
            output << tmp << " ";
		}
		output << "\n";
	}

	output.close();
    
    return 0;
}
int Miscellaneous::read_matrix_from_file(string filename, string path, bool** I, TYPE_INDEX num_row, TYPE_INDEX num_col)
{
    ifstream input;
    TYPE_INDEX row, col;
    input.open(path+filename);

    for(row = 0 ; row < num_row;row++)
    {
        for(col = 0 ; col < num_col; col ++)
        {
               input>> I[row][col];
        }
    }
	
    input.close();
    
    return 0;

}
int Miscellaneous::write_array_to_file(string filename, string path, TYPE_COUNTER* arr, TYPE_INDEX size)
{
    std::ofstream output;
	TYPE_INDEX i;
    
	output.open(path+filename);

	for(i = 0; i < size; i++)
    {
        output << arr[i] << " ";
    }
    
	output.close();
    
    return 0;
}
int Miscellaneous::read_array_from_file(string filename, string path, TYPE_COUNTER* arr, TYPE_INDEX size)
{
    ifstream input;
    TYPE_INDEX i;
    input.open(path+filename);
    
    for(i = 0 ; i < size;i++)
    {
        input>> arr[i];
    }
	
    input.close();
    return 0;
}
int Miscellaneous::write_array_to_file(string filename, string path, bool* arr, TYPE_INDEX size)
{
    std::ofstream output;
	TYPE_INDEX i;
    
	output.open(path+filename);
	for(i = 0; i < size; i++)
    {
        output << arr[i] << " ";
    }

	output.close();
    
    return 0;
}
int Miscellaneous::read_array_from_file(string filename, string path, bool* arr, TYPE_INDEX size)
{
    ifstream input;
    TYPE_INDEX i;
    input.open(path+filename);
    
    for(i = 0 ; i < size;i++)
    {
        input>> arr[i];
    }
	
    input.close();
    return 0;
}
int Miscellaneous::write_counter_to_file(string filename, string path, TYPE_COUNTER n)
{
    std::ofstream output;
    
	output.open(path+filename);
    output << n;
	output.close();
    
    return 0;
}
int Miscellaneous::read_counter_from_file(string filename, string path, TYPE_COUNTER &n)
{
    ifstream input;
    input.open(path+filename);
    input>> n;
    input.close();
    
    return 0;
}
int Miscellaneous::write_list_to_file(string filename, string path, vector<TYPE_INDEX> lst)
{
    
     std::ofstream output;
     output.open(path+filename);
     TYPE_INDEX i;
     if(lst.size()==0)
         output<<ULONG_MAX;
     for ( i = 0 ; i <lst.size();i++)
     {
         output<<lst[i] << " ";
     }
     output.close();
     return 0;
}
int Miscellaneous::read_list_from_file(string filename, string path, vector<TYPE_INDEX> &lst)
{
    ifstream input;
    input.open(path+filename);
    TYPE_INDEX in = ULONG_MAX;
    lst.clear();
    while(input>>in)
    {
        if(in!=ULONG_MAX)
            lst.push_back(in);
    }
    input.close();
    
    return 0;
}

int Miscellaneous::writeHash_table_token(TYPE_GOOGLE_DENSE_HASH_MAP &rT, string filename, string path)
{
    TYPE_GOOGLE_DENSE_HASH_MAP::iterator it;
    TYPE_GOOGLE_DENSE_HASH_MAP::iterator it_end = rT.end();
    unsigned char tmp[TRAPDOOR_SIZE];
    string filename_with_path = path + filename;
    
    FILE *foutput = fopen(filename_with_path.c_str(),"wb+");;
    for(it = rT.begin(); it!=it_end; it++)
    {
        //write key
        memset(tmp,0,TRAPDOOR_SIZE);
        memcpy(tmp,it->first.get_data(),TRAPDOOR_SIZE);
        fwrite(tmp,TRAPDOOR_SIZE,1,foutput);
        //write value
        for(int i = 0 ; i < NUM_SERVERS ; i ++)
        {
            TYPE_INDEX curIdx = it->second->getIndexBySID(i);
            fwrite(&curIdx,sizeof(TYPE_INDEX),1,foutput);
        }
    }
    fclose(foutput);
}
int Miscellaneous::readHash_table_token(TYPE_GOOGLE_DENSE_HASH_MAP &rT, string filename, string path, TYPE_INDEX n)
{
    TYPE_GOOGLE_DENSE_HASH_MAP::iterator it;
    TYPE_GOOGLE_DENSE_HASH_MAP::iterator it_end = rT.end();
    unsigned char tmp[TRAPDOOR_SIZE];
    string filename_with_path = path + filename;
    FILE* finput = fopen(filename_with_path.c_str(), "rb" );
    for(TYPE_INDEX i = 0 ; i < n ; i++)
    {
        fread(&tmp,TRAPDOOR_SIZE,1,finput);
        hashmap_key_class trapdoor(tmp,TRAPDOOR_SIZE);
        rT[trapdoor] = new TokenInfo();
        for(int k = 0 ; k < NUM_SERVERS; k++)
        {
            TYPE_INDEX curIdx = 0;
            fread(&curIdx,sizeof(TYPE_INDEX),1,finput);
            rT[trapdoor]->setIndex(curIdx,k);
        }
        
        
    }
    fclose(finput);
}
