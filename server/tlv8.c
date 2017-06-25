#include "debug.h"
#include "tlv8.h"

void ICACHE_FLASH_ATTR
tlv8_parse(char *pbuf, uint16_t len, char *objects[], uint16_t objects_len[]) {
    uint8_t t, i;

    for (i = 0; i < TLVNUM; i++) {
        objects_len[i] = 0; //reset any old values
    }  
    
    for (uint16_t j = 0; j < len; ) {
        t = pbuf[j++]; // type
#if DEBUG_LEVEL <= TRACE
        os_printf("t:%d-",t);
#endif
        // verify validity of type
        i = objects_len[t]; // old length is insertionpoint
        objects_len[t] += pbuf[j++]; //new length

#if DEBUG_LEVEL <= TRACE
        os_printf("n:%d\n",objects_len[t]);
#endif
        for (uint16_t l = 0; l < (objects_len[t] - i); l++ ) {
            objects[t][i + l] = pbuf[j++];
        }
    }
    
#if DEBUG_LEVEL <= TRACE
    for (uint8_t i = 0; i < TLVNUM; i++)    {
        if (objects_len[i]) {
            os_printf("%d:",i);
            for (uint16_t j = 0; j < objects_len[i]; j++ ) {
                os_printf("%02x",objects[i][j]);
            }
            os_printf("\n");
        }
    }
#endif
}

void ICACHE_FLASH_ATTR
tlv8_add(char *pbuf, uint16_t *index, uint8_t type, uint16_t len, char *value) {
    uint16_t length = 0;  //encoded size for chunk size
    uint16_t done = 0;    //part already transferred
    char *pindex;
    char chunksize[6]; //to prevent trailing 0 to overwrite first type
    
    pindex = pbuf + *index;
    LOG(TRACE, "i = %d, t = %d, l = %d", *index, type, len)

    if (len < 14) {
        length = len + 2; // t + l = 2
        sprintf(pindex, "%x\r\n", length); //one digit
        length += 3; //chunksize text
        *(pindex + 3) = (char)type;
        *(pindex + 4) = (char)len;
        memcpy(pindex + 5, value, len);
    } else if (len < 254) {
        length = len + 2; // t + l =2
        sprintf(pindex, "%x\r\n", length); //now two digits
        length += 4; //chunksize text
        *(pindex + 4) = (char)type;
        *(pindex + 5) = (char)len;
        memcpy(pindex + 6, value, len);
    } else {  //>253
        while (len> 255) {
            *(pindex + 5) = (char)type;
            *(pindex + 6) = (char)255;
            memcpy(pindex + 7, value + done, 255);
            len -= 255;
            done += 255;
            length += 257;
            pindex += 257;
        }
        length += len + 2; // t + l =2
        sprintf(chunksize, "%x\r\n", length); //now three digits with trailing zero
        memcpy(pbuf + *index, chunksize, 5);
        length += 5; //chunksize text
        *(pindex + 5) = (char)type;
        *(pindex + 6) = (char)len;
        memcpy(pindex + 7, value + done, len);
    }
    *index += length;
    memcpy(pbuf + *index, "\r\n", 2);
    *index += 2;
}

void ICACHE_FLASH_ATTR tlv8_close(char *pbuf, uint16_t *index) {
    memcpy(pbuf + *index, "0\r\n\r\n", 5);
    *index += 5;
}
