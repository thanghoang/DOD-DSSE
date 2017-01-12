#ifndef SEARCH_TOKEN_H
#define SEARCH_TOKEN_H

typedef struct SearchToken{
	TYPE_INDEX row_index;          //i
	unsigned char row_key[BLOCK_CIPHER_SIZE] = {'\0'};         //r_i
    unsigned char row_old_key[BLOCK_CIPHER_SIZE] = {'\0'};     //\bar{r}_i
    bool hasRow_key = false;
}SEARCH_TOKEN;

#endif 