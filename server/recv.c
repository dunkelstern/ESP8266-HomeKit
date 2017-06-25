#include <esp_common.h>
#include <espconn.h>
#include <cJSON.h>

#include "debug.h"

#include "crypto.h"
#include "url.h"
#include "parser.h"
#include "send.h"

uint32_t dat_sumlength = 0;
char *precvbuffer;

extern bool pairing;
extern bool halfpaired;

/******************************************************************************
 * FunctionName : save_data
 * Description  : put info in buffer
 * Parameters   : precv  -- data to save
 *                length -- The length of received data
 * Returns      : boolean if OK
*******************************************************************************/
LOCAL bool ICACHE_FLASH_ATTR
save_data(char *precv, uint16_t length) {
    bool flag = false;
    char length_buf[10] = {0};
    char *ptemp = NULL;
    char *pdata = NULL;
    uint16 headlength = 0;
    static uint32 totallength = 0;

    ptemp = (char *)strstr(precv, "\r\n\r\n");  //dangerous assumption in case of binary

    if (ptemp != NULL) {
        length -= ptemp - precv;
        length -= 4;
        totallength += length;
        headlength = ptemp - precv + 4;
        pdata = (char *)strstr(precv, "Content-Length: ");

        if (pdata != NULL) {
            pdata += 16;
            precvbuffer = (char *)strstr(pdata, "\r\n");

            if (precvbuffer != NULL) {
                memcpy(length_buf, pdata, precvbuffer - pdata);
                dat_sumlength = atoi(length_buf);
                LOG(TRACE, "dsl: %d, tl: %d, hl: %d, len: %d", dat_sumlength, totallength, headlength, length)
            }
        } else {
            if (totallength != 0x00){
                totallength = 0;
                dat_sumlength = 0;
                return false;
            }
        }
        if ((dat_sumlength + headlength) >= 1024) { // FIXME: protection to long packets???
            precvbuffer = (char *)zalloc(headlength + 1);
            memcpy(precvbuffer, precv, headlength + 1);  // only header copied
        } else {
            LOG(DEBUG, "normal packet saved");
            precvbuffer = (char *)zalloc(dat_sumlength + headlength + 1);
            memcpy(precvbuffer, precv, dat_sumlength + headlength);
        }
    } else {  // assuming a multipacket message
        LOG(DEBUG, "multipacket extension saved");

        if (precvbuffer != NULL) {
            totallength += length;
            memcpy(precvbuffer + strlen(precvbuffer), precv, length);  // FIXME: not binary proof
        } else {
            totallength = 0;
            dat_sumlength = 0;
            return false;
        }
    }

    if (totallength == dat_sumlength) {
        totallength = 0;
        dat_sumlength = 0;
        return true;
    } else {
        return false;
    }
}

/******************************************************************************
 * FunctionName : server_recv
 * Description  : Processing the received data from the server
 * Parameters   : arg -- Additional argument to pass to the callback function
 *                pusrdata -- The received data (or NULL when the connection has been closed!)
 *                length -- The length of received data
 * Returns      : none
*******************************************************************************/
void ICACHE_FLASH_ATTR
server_recv(void *arg, char *pusrdata, uint16_t length) {
    // FIXME: use correct HTTP server impl or at least split up this monster
    struct espconn *ptrespconn = arg;
    crypto_parm *pcryp = ptrespconn->reserve;

    // FIXME: semaphore really needed?
    if (pcryp && xSemaphoreTake(pcryp->semaphore, 0)){
    
        char flash[] = "killthesignature";
        uint16_t *objects_len = pcryp->objects_len;
        char *objects[TLVNUM]= {
            pcryp->object + 0x1c0,//0
            pcryp->object + 0x60, //1
            NULL,
            pcryp->object,      //3
            pcryp->object + 0x180,//4
            pcryp->object + 0xb0, //5
            pcryp->object + 0x1c1,//6
            NULL,
            NULL,
            NULL,
            pcryp->object + 0x20, //10
            pcryp->object + 0x1c2 //11
        }; //read header file for above magic

        int datlen;
        URL_Frame *pURL_Frame = NULL;
        char *pParseBuffer = NULL;
        bool delegated = false;
        bool parse_flag = false;
        char *chars;
        uint32_t sector = 0x13;
        uint32_t start = sector * 0x1000;
    
        LOG(DEBUG, "server got a packet from %d.%d.%d.%d:%d at %d",
            ptrespconn->proto.tcp->remote_ip[0],
            ptrespconn->proto.tcp->remote_ip[1],
            ptrespconn->proto.tcp->remote_ip[2],
            ptrespconn->proto.tcp->remote_ip[3],
            ptrespconn->proto.tcp->remote_port,
            system_get_time()/1000
        );

        LOG(TRACE, "len: %u",length);
        if (pcryp->encrypted) {
            decrypt(pcryp, pusrdata, &length); //length will be updated
        }
        LOG(TRACE, "len: %u", length);
        
        if (!check_data(pusrdata, length)) {
            LOG(TRACE, "content length mismatch: goto temp exit");
            goto _temp_exit;
        }
        datlen = dat_sumlength;
        
        parse_flag = save_data(pusrdata, length);
        if (parse_flag == false) {
            response_send(pcryp, false);
        }

        pURL_Frame = (URL_Frame *)zalloc(sizeof(URL_Frame));
        parse_url(precvbuffer, pURL_Frame);

        switch (pURL_Frame->Type) {
            case GET: {
                LOG(DEBUG, "GET/S: %s C: %s F: %s",
                    pURL_Frame->pSelect,
                    pURL_Frame->pCommand,
                    pURL_Frame->pFilename
                );

                if (strcmp(pURL_Frame->pSelect, "identify") == 0) {
                    LOG(DEBUG, "identify");

                    //FIXME: do identify routine as a task?
                    h204_send(pcryp);
                }
                if (strcmp(pURL_Frame->pSelect, "accessories") == 0 && pcryp->encrypted) {
                    LOG(DEBUG, "accessories");
                    if (halfpaired) {
                        LOG(DEBUG, "halfpaired");

                        flash[0] = 0x00;
                        flash[1] = 0x7f;
                        flash[2] = 0xff;
                        flash[3] = 0xff;
                        spi_flash_write(start, (uint32_t *)flash, 4);

                        LOG(DEBUG, "postwrite");
                        halfpaired=0;
                        pairing=0;
                    }

                    pcryp->state = 6;
                    xQueueSendToFront(crypto_queue, &pcryp, 0);
                    delegated = true;
                    LOG_HEAP("out of TaskCreate");
                }
                if (strcmp(pURL_Frame->pSelect, "characteristics") == 0 && strcmp(pURL_Frame->pCommand, "id") == 0 && pcryp->encrypted) {
                    LOG(DEBUG, "characteristics");
                    chars = parse_cgi(pURL_Frame->pFilename);
                    data_send(pcryp, true, chars);
                    free(chars);
                }
#ifdef FACTORY
                if (strcmp(pURL_Frame->pSelect, "factory") == 0 && !pcryp->encrypted) {
                    LOG(WARN, "factory reset");
                    spi_flash_write(start + 4080, (uint32 *)flash, 16); //mutilate the signature
                    system_restart();
                }
#endif
                break;
            }

            case PUT: {
                LOG(DEBUG, "PUT/S: %s C: %s F: %s",
                    pURL_Frame->pSelect,
                    pURL_Frame->pCommand,
                    pURL_Frame->pFilename
                );

                pParseBuffer = (char *)strstr(precvbuffer, "\r\n\r\n");
                if (pParseBuffer == NULL) {
                    break;
                }

                pParseBuffer += 4;
                HEXDUMP(TRACE, "pParseB", pParseBuffer, datlen);

                if (strcmp(pURL_Frame->pSelect, "characteristics") == 0 && pcryp->encrypted) {
                    LOG(DEBUG, "characteristics");
                    parse_chas(pcryp, pParseBuffer);
                    h204_send(pcryp);
                }

                break;
            }
                
            case POST: {
                LOG(DEBUG, "POST/S: %s C: %s F: %s",
                    pURL_Frame->pSelect,
                    pURL_Frame->pCommand,
                    pURL_Frame->pFilename
                );

                pParseBuffer = (char *)strstr(precvbuffer, "\r\n\r\n");
                if (pParseBuffer == NULL) {
                    break;
                }

                pParseBuffer += 4;
                HEXDUMP(TRACE, "pParseB", pParseBuffer, datlen);

                if (strcmp(pURL_Frame->pSelect, "identify") == 0) {
                    LOG(DEBUG, "identify");
                    //FIXME: do identify routine as a task?
                    h204_send(pcryp);
                }

                if (strcmp(pURL_Frame->pSelect, "pairings") == 0 && pcryp->encrypted) {
                    LOG(DEBUG, "pairings");

                    //parse tlv8
                    tlv8_parse(pParseBuffer,datlen,objects,objects_len); 

                    //based on 06 value switch to a routine in srpsteps.c which sends chunked tlv8 body
                    switch (objects[0][0]) {
                        case 0x03:
                            LOG_HEAP("pairings 1 (0x03)");
                            pcryp->state = 7;
                            xQueueSendToFront(crypto_queue, &pcryp, 0);
                            delegated = true;
                            LOG_HEAP("pairings 2 (0x03)");
                            break;

                        case 0x04:
                            LOG_HEAP("pairings 1 (0x04)");
                            pcryp->state = 8;
                            xQueueSendToFront(crypto_queue, &pcryp, 0);
                            delegated = true;
                            LOG_HEAP("pairings 1 (0x04)");
                            break;
                    }
                }

                if (strcmp(pURL_Frame->pSelect, "pair-setup") == 0) {
                    LOG(DEBUG, "pair-setup");

                    //parse tlv8
                    tlv8_parse(pParseBuffer,datlen,objects,objects_len); 

                    //based on 06 value switch to a routine in srpsteps.c which sends chunked tlv8 body
                    switch (objects[6][0]) {
                        case 0x01:
                            LOG_HEAP("pair-setup 1 (0x01)");
                            crypto_setup1(pcryp);
                            LOG_HEAP("pair-setup 2 (0x01)");
                            break;

                        case 0x03:
                            LOG_HEAP("pair-setup 1 (0x03)");
                            pcryp->state = 2;
                            xQueueSendToFront(crypto_queue, &pcryp, 0);
                            delegated = true;
                            LOG_HEAP("pair-setup 2 (0x03)");
                            break;

                        case 0x05:
                            LOG_HEAP("pair-setup 1 (0x05)");
                            pcryp->state = 3;
                            xQueueSendToFront(crypto_queue, &pcryp, 0);
                            delegated = true;
                            LOG_HEAP("pair-setup 1 (0x05)");
                            break;
                    }
                }

                if (strcmp(pURL_Frame->pSelect, "pair-verify") == 0) {
                    LOG(DEBUG, "pair-verify");

                    //parse tlv8
                    tlv8_parse(pParseBuffer,datlen,objects,objects_len); 

                    //based on 06 value switch to a routine in srpsteps.c which sends chunked tlv8 body
                    switch (objects[6][0]) {
                        case 0x01:
                            LOG_HEAP("pair-verify 1 (0x01)");
                            pcryp->state = 4;
                            xQueueSendToBack(crypto_queue, &pcryp, 0);
                            delegated = true;
                            LOG_HEAP("pair-verify 2 (0x01)");
                            break;

                        case 0x03:
                            LOG_HEAP("pair-verify 1 (0x03)");
                            pcryp->state = 5;
                            xQueueSendToFront(crypto_queue, &pcryp, 0);
                            delegated = true;
                            LOG_HEAP("pair-verify 2 (0x03)");
                            break;
                    }
                }

                // FIXME: Do we actually have to respond to these?
                if (strcmp(pURL_Frame->pSelect, "config") == 0 && strcmp(pURL_Frame->pCommand, "command") == 0) {
                    if (strcmp(pURL_Frame->pFilename, "reboot") == 0) {
                    } else if (strcmp(pURL_Frame->pFilename, "wifi") == 0) {
                    } else if (strcmp(pURL_Frame->pFilename, "switch") == 0) {
                    } else {
                        response_send(pcryp, false);
                    }
                }
            
                break;
            }
        }

        if (precvbuffer != NULL){
            free(precvbuffer);
            precvbuffer = NULL;
        }

        free(pURL_Frame);
        pURL_Frame = NULL;
        
        _temp_exit:
            ;
        
        if (!delegated) xSemaphoreGive(pcryp->semaphore);
    }
}
