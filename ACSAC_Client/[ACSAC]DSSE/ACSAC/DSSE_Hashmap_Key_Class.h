/*
 * DynamicSSE_Hashmap_Key_Class.h
 *
 *  Created on: Oct 24, 2013
 *      Author: anvesh
 */

#ifndef DYNAMICSSE_HASHMAP_KEY_CLASS_H_
#define DYNAMICSSE_HASHMAP_KEY_CLASS_H_

#include <stdlib.h>
#include <string.h>									// For string related operations
#include <algorithm>								// For std::copy utility
#include <iostream>									// For standard I/O stream

using namespace std;

/**
 * A class that is used as the key type in hashmap
 * Anvesh Ragi                   10-21-2013              Function Created
 */
class hashmap_key_class {

private:
	unsigned char *pData;
	int			   data_length;

public:

	// Constructors
	hashmap_key_class();				// Default Constructor
	hashmap_key_class(int data_len);
	hashmap_key_class(const unsigned char *pIndata, int data_len);
	hashmap_key_class(const hashmap_key_class &rObj);

	// Destructor
	~hashmap_key_class();

	// Getters
	int get_data_length() const;
	unsigned char* get_data() const;

	// Setter
	void set_data(unsigned char* data, int data_len);

	// Prints the data
	void print_data() const;

	// Prints the data length
	void print_data_length() const;

	//equal comparison operator for this class
	bool operator()(const hashmap_key_class &rObj1, const hashmap_key_class &rObj2) const;
	// bool operator==(const hashmap_key_class &rObj) const;

	//hashing operator for this class
	size_t operator()(const hashmap_key_class &rObj) const;
	// size_t operator()() const;

	// Assignment operator
	hashmap_key_class& operator=(const hashmap_key_class &rObj);
	hashmap_key_class& operator=(const unsigned char *pIndata);
};

#endif /* DYNAMICSSE_HASHMAP_KEY_CLASS_H_ */
