#ifndef server__tlv8_h__included
#define server__tlv8_h__included

#include <esp_common.h>

#define TLVNUM 12

/******************************************************************************
 * FunctionName : tlv8_parse
 * Description  : take incoming buffer and deliver tlv structure array
 * Parameters   : pbuf -- pointer to buffer
 *                len -- the length of the buffer
 *                objects -- the pointer to the struct array
*                 objects_len -- array of lengths of the struct
 * Returns      :
*******************************************************************************/
void ICACHE_FLASH_ATTR
tlv8_parse(char *pbuf, uint16_t len, char *objects[], uint16_t objects_len[]);

/******************************************************************************
 * FunctionName : tlv8_add
 * Description  : adds one item to buffer in chunked and tlv8 encoding
 * Parameters   : pbuf -- pointer to buffer
 *                index -- distance to buffer insertion point will be updated
 *                type -- type of item to add
 *                len -- the length of the value to add (max 4094)
 *                value -- pointer to buffer with value content
 * Returns      :
*******************************************************************************/
void ICACHE_FLASH_ATTR
tlv8_add(char *pbuf, uint16_t *index, uint8_t type, uint16_t len, char *value);

/******************************************************************************
 * FunctionName : tlv8_close
 * Description  : add the final chunked close item of zero length
 * Parameters   : pbuf -- pointer to buffer
 *                index -- distance to buffer insertion point will be updated
 * Returns      :
*******************************************************************************/
void ICACHE_FLASH_ATTR
tlv8_close(char *pbuf, uint16_t *index);

#endif