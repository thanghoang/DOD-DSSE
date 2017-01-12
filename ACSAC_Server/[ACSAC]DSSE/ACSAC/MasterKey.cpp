#include "MasterKey.h"

MasterKey::MasterKey()
{
}

MasterKey::~MasterKey()
{
}

/**
 * Function Name: isNULL
 *
 * Description:
 * Checks if the Master Key is NULL
 *
 * @param 
 * @return 0 if NOT NULL, 1 if NULL
 * History
 * Name							Date					Comment
 * ---------------------------------------------------------------------
 * Thang Hoang 				11-06-2015				Function Created
 */
bool MasterKey::isNULL()
{
    if(this->key1 ==NULL || this->key2 == NULL || this->key3 == NULL)
        return 1;
    return 0;
}