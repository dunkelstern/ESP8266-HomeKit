#include <esp_common.h>

#include "debug.h"
#include "url.h"

/******************************************************************************
 * FunctionName : parse_url
 * Description  : parse the received data from the server
 * Parameters   : precv -- the received data
 *                purl_frame -- the result of parsing the url
 * Returns      : none
*******************************************************************************/
void ICACHE_FLASH_ATTR
parse_url(char *precv, URL_Frame *purl_frame) {
    char *str = NULL;
    uint8 length = 0;
    char *pbuffer = NULL;
    char *pbufer = NULL;

    if (purl_frame == NULL || precv == NULL) {
        return;
    }

    pbuffer = (char *)strstr(precv, "Host:");

    if (pbuffer != NULL) {
        length = pbuffer - precv;
        pbufer = (char *)zalloc(length + 1);
        pbuffer = pbufer;
        memcpy(pbuffer, precv, length);
        memset(purl_frame->pSelect, 0, URLSize);
        memset(purl_frame->pCommand, 0, URLSize);
        memset(purl_frame->pFilename, 0, URLSize);

        if (strncmp(pbuffer, "GET ", 4) == 0) {
            purl_frame->Type = GET;
            pbuffer += 4;
        } else if (strncmp(pbuffer, "POST ", 5) == 0) {
            purl_frame->Type = POST;
            pbuffer += 5;
        } else if (strncmp(pbuffer, "PUT ", 4) == 0) {
            purl_frame->Type = PUT;
            pbuffer += 4;
        }

        pbuffer ++; // to skip the /
        str = (char *)strstr(pbuffer, "?");

        if (str != NULL) {
            length = str - pbuffer;
            memcpy(purl_frame->pSelect, pbuffer, length);
            str ++;
            pbuffer = (char *)strstr(str, "=");

            if (pbuffer != NULL) {
                length = pbuffer - str;
                memcpy(purl_frame->pCommand, str, length);
                pbuffer ++;
                str = (char *)strstr(pbuffer, "&");

                if (str != NULL) {
                    length = str - pbuffer;
                    memcpy(purl_frame->pFilename, pbuffer, length);
                } else {
                    str = (char *)strstr(pbuffer, " HTTP");

                    if (str != NULL) {
                        length = str - pbuffer;
                        memcpy(purl_frame->pFilename, pbuffer, length);
                    }
                }
            }
        } else {
            str = (char *)strstr(pbuffer, " HTTP");

            if (str != NULL) {
                length = str - pbuffer;
                memcpy(purl_frame->pSelect, pbuffer, length);
            }
        }

        free(pbufer);
    } else {
        return;
    }
}
