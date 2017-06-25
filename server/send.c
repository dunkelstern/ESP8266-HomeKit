#include <esp_common.h>
#include <espconn.h>
#include <cJSON.h>

#include "debug.h"
#include "send.h"
#include "esp_reverse_engineered.h"
#include "crypto.h"
#include "parser.h"

acc_item acc_items[MAXITM+1];
extern espconn_msg *plink_active;
extern cJSON *root;

/******************************************************************************
 * FunctionName : acc_send
 * Description  : processing the data as http format and send to the client or server
 * Parameters   : arg -- argument to set for client or server
 * Returns      :
*******************************************************************************/
void ICACHE_FLASH_ATTR
acc_send(void *arg) {
    uint16_t length = 0;
    char *pbuf = NULL;
    char httphead[128] = {0};
    char *accessories = cJSON_PrintUnformatted(root);
    crypto_parm *pcryp = arg;
    uint16_t len = strlen(accessories);
    
    sprintf(httphead, \
        "HTTP/1.1 200 OK\r\n" \
        "Content-Length: %d\r\n" \
        "Connection: keep-alive\r\n" \
        "Content-type: application/hap+json\r\n" \
        "\r\n",
        len
    );
    length = strlen(httphead) + len;
    pbuf = (char *)zalloc(length + 1 + 54); //better calculate +18 per 0x400
    memcpy(pbuf, httphead, strlen(httphead));
    memcpy(pbuf + strlen(httphead), accessories, len);

    if (pcryp->encrypted) {
        encrypt(pcryp, pbuf, &length);
    }
    if (!pcryp->stale){
        LOG(TRACE, "length: 0x%04x", length);
        int result = espconn_sent(pcryp->pespconn, pbuf, length);

        LOG_HEAP("acc_send");
        LOG(DEBUG, "acc send result: %d", result);
    }
    
    if (pbuf) {
        free(pbuf);
        pbuf = NULL;
    }
    if (accessories) {
        free(accessories);
        accessories = NULL;
    }
}

void change_value(int aid, int iid, cJSON *item) {
    cJSON *value;
    char *format;

    format = cJSON_GetObjectItem(acc_items[iid].json, "format")->valuestring;
    value = cJSON_GetObjectItem(acc_items[iid].json, "value");

    switch (item->type) {
        case cJSON_Number:
            LOG(TRACE, "chas: %d.%d = valN -> %s", aid, iid, format);
            if (value && !strcmp(format,"bool")) {
                value->type == (item->valueint == 0) ? 0 : 1;
            } else if(value && !strcmp(format, "int")) {
                value->valueint = item->valueint;
                value->valuedouble = item->valuedouble;
            }
            break;

        case cJSON_String:
            LOG(TRACE, "chas: %d.%d = valS -> %s", aid, iid, format);
            if (value && !strcmp(format,"string")) {
                format = value->valuestring;
                value->valuestring = item->valuestring;
                item->valuestring = format;
            }
            break;

        case cJSON_False:
            LOG(TRACE, "chas: %d.%d = valF -> %s", aid, iid, format);
            if (value && !strcmp(format,"bool")) {
                value->type = 0;
            } 
            break;

        case cJSON_True:
            LOG(TRACE, "chas: %d.%d = valT -> %s", aid, iid, format);
            if (value && !strcmp(format,"bool")) {
                value->type = 1;
            }
            break;

        default:
            LOG(TRACE, "chas: %d.%d = valX -> %s", aid, iid, format);
            break;
    }
}

void send_events(void *arg, int aid, int iid) {
    espconn_msg *plist = plink_active;
    crypto_parm *pcryp = arg;
    struct espconn *pespconn = NULL;
    char *json;
    char tag[5];

    if (pcryp) {
        pespconn = pcryp->pespconn;
    } 
    
    while(plist != NULL){
        if ((plist->pespconn!=pespconn) //do not send to self!
            && (pcryp=plist->pespconn->reserve)  //does it have a valid pointer
            && (pcryp->connectionid&acc_items[iid].events) ) { //compare bitmaps

            if (xSemaphoreTake(pcryp->semaphore,5)) { //if busy, wait
                sprintf(tag, "%d.%d", aid, iid);
                json = parse_cgi(tag);
                event_send(pcryp, json);
                free(json);
                xSemaphoreGive(pcryp->semaphore);
            }
        }
        plist = plist->pnext;
    }
}

/******************************************************************************
 * FunctionName : tlv8_send
 * Description  : processing the data as http format and send to the client or server; also frees the payload memory
 * Parameters   : arg -- argument to set for client or server
 *                psend -- The binary send data in chunked tlv8 format
 *                len -- the length of the send data
 * Returns      :
*******************************************************************************/
void ICACHE_FLASH_ATTR
tlv8_send(void *arg, char *pbuf, uint16_t len) {
    crypto_parm *pcryp = arg;
    uint16_t length = 0;
    char *psend = NULL;
    char httphead[] = \
        "HTTP/1.1 200 OK\r\n" \
        "Content-type: application/pairing+tlv8\r\n" \
        "Connection: keep-alive\r\n" \
        "Transfer-Encoding: chunked\r\n" \
        "\r\n";

    length = strlen(httphead) + len;
    psend = (char *)zalloc(length + 1 + 18);
    memcpy(psend, httphead, strlen(httphead));
    memcpy(psend + strlen(httphead), pbuf, len);

    if (pbuf != NULL){  // FIXME: consider to make calling party responsible
        free(pbuf);
        pbuf = NULL;
    }

    #if DEBUG_LEVEL <= TRACE
        for (int i = 0; i < length; i++) {
            os_printf("%02x", psend[i]);
        }
        os_printf("\nto be sent by tlv8_send routine\n");
        LOG(TRACE, "arg=%08x, ptrespconn=%08x, pcryp=%08x", arg, pcryp->pespconn, pcryp)
    #endif

    // encrypt
    if (pcryp->encrypted) {
        encrypt(pcryp, psend, &length);
    }

    if (!pcryp->stale){
        int result = espconn_sent(pcryp->pespconn, psend, length);
        LOG(DEBUG, "send result: %d\n", result);
    }
    if (psend) {
        free(psend);
        psend = NULL;
    }
}


/******************************************************************************
 * FunctionName : event_send
 * Description  : processing the data as http format and send to the client or server
 * Parameters   : arg -- argument to set for client or server
 *                psend -- The send data
 * Returns      :
*******************************************************************************/
void ICACHE_FLASH_ATTR
event_send(void *arg, char *psend) {
    crypto_parm *pcryp = arg;
    uint16 length = 0;
    char *pbuf = NULL;
    char httphead[256] = {0};

    sprintf(httphead, 
        "EVENT/1.0 200 OK\r\n" \
        "Content-type: application/hap+json\r\n" \
        "Content-Length: %d\r\n" \
        "\r\n",
        strlen(psend)
    );

    length = strlen(httphead) + strlen(psend);
    pbuf = (char *)zalloc(length + 1 + 36); //better calculate +18 per 0x400
    memcpy(pbuf, httphead, strlen(httphead));
    memcpy(pbuf + strlen(httphead), psend, strlen(psend));

    if (pcryp->encrypted) {
        encrypt(pcryp, pbuf, &length);
    }

    if (!pcryp->stale){
        if (pcryp->pespconn->state == ESPCONN_CONNECT) {
            espconn_sent(pcryp->pespconn, pbuf, length);
        } else {
            LOG(ERROR, "event aborted");
        }
    }

    if (pbuf) {
        free(pbuf);
        pbuf = NULL;
    }
}

/******************************************************************************
 * FunctionName : h204_send
 * Description  : processing the data as http format and send to the client or server
 * Parameters   : arg -- argument to set for client or server
 * Returns      :
*******************************************************************************/
void ICACHE_FLASH_ATTR
h204_send(void *arg) {
    crypto_parm *pcryp = arg;
    uint16 length = 0;
    char httphead[118]; //add 18 for encryption
    
    sprintf(httphead, 
        "HTTP/1.1 204 No Content\r\n" \
        "Connection: keep-alive\r\n" \
        "Content-type: application/hap+json\r\n" \
        "\r\n"
    );

    length = strlen(httphead);
    if (pcryp->encrypted) {
        encrypt(pcryp, httphead, &length);
    }

    LOG(TRACE, "length: 0x%04x", length);
    int result = espconn_sent(pcryp->pespconn, httphead, length);

    LOG_HEAP("h204_send");
    LOG(DEBUG, "send result: %d", result);
}

/******************************************************************************
 * FunctionName : data_send
 * Description  : processing the data as http format and send to the client or server
 * Parameters   : arg -- argument to set for client or server
 *                responseOK -- true or false
 *                psend -- The send data
 * Returns      :
*******************************************************************************/
void ICACHE_FLASH_ATTR
data_send(void *arg, bool responseOK, char *psend) {
    crypto_parm *pcryp = arg;
    uint16 length = 0;
    char *pbuf = NULL;
    char httphead[256] = {0};

    if (responseOK) {
        sprintf(httphead,
            "HTTP/1.0 200 OK\r\n" \
            "Content-Length: %d\r\n",
            psend ? strlen(psend) : 0
        );

        if (psend) {
            sprintf(httphead + strlen(httphead),
                "Connection: keep-alive\r\n" \
                "Content-type: application/hap+json\r\n" \
                "\r\n"
            );
            length = strlen(httphead) + strlen(psend);
            pbuf = (char *)zalloc(length + 1 + 36); //better calculate +18 per 0x400
            memcpy(pbuf, httphead, strlen(httphead));
            memcpy(pbuf + strlen(httphead), psend, strlen(psend));
        } else {
            sprintf(httphead + strlen(httphead), "\n");
            length = strlen(httphead);
        }
    } else {
        sprintf(httphead,
            "HTTP/1.0 400 BadRequest\r\n" \
            "Content-Length: 0\r\n" \
            "Server: lwIP/1.4.0\r\n"
            "\r\n"
        );
        length = strlen(httphead);
    }

    if (psend) {
        if (pcryp->encrypted) {
            encrypt(pcryp, pbuf, &length);
        }
        espconn_sent(pcryp->pespconn, pbuf, length);
    } else {
        espconn_sent(pcryp->pespconn, httphead, length);
    }

    if (pbuf) {
        free(pbuf);
        pbuf = NULL;
    }
}

/******************************************************************************
 * FunctionName : response_send
 * Description  : processing the send result
 * Parameters   : arg -- argument to set for client or server
 *                responseOK --  true or false
 * Returns      : none
*******************************************************************************/
void ICACHE_FLASH_ATTR
response_send(void *arg, bool responseOK) {
    data_send(arg, responseOK, NULL);
}
