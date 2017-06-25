#include <esp_common.h>
#include <cJSON.h>

#include "debug.h"
#include "parser.h"
#include "send.h"
#include "crypto.h"

extern uint32_t dat_sumlength;

// take aid.iid string and return chars string / only single digit aid!
char *parse_cgi(char *in) {
    char *out = strtok(in, ",");
    cJSON *chars, *item;
    cJSON *items = cJSON_CreateArray();
    int aid, iid;

    chars = cJSON_CreateObject();
    cJSON_AddItemToObject(chars, "characteristics", items); //FIXME: consider a addAccessory function
    while(out) {
        aid = out[0] - 0x30; //FIXME: only supporting single digit aid
        iid = atoi(out + 2);
        
        //callback update
        if (acc_items[iid].change_cb) {
            acc_items[iid].change_cb(
                aid,
                iid,
                cJSON_GetObjectItem(acc_items[iid].json,"value"),
                2 // update
            );
        } 

        item = cJSON_CreateObject();
        cJSON_AddItemToArray(items, item);
        cJSON_AddNumberToObject(item, "aid", aid);
        cJSON_AddNumberToObject(item, "iid", iid);
        cJSON_AddItemReferenceToObject(
            item,
            "value",
            cJSON_GetObjectItem(acc_items[iid].json,"value") // FIXME: crash if points to null?
        );

        // fetch next
        out = strtok(NULL, ",");
    }

    // fetch final json
    out = cJSON_PrintUnformatted(chars);

    // cleanup
    cJSON_Delete(chars);
    return out;
}

// FIXME: flash attr, naming?
//parse this: {"characteristics":[{"aid":1,"iid":9,"ev":false},{"aid":1,"iid":12,"ev":false}]}
//and   this: {"characteristics":[{"aid":1,"iid":12,"value":1}]}
void parse_chas(void *arg, char *in) {
    crypto_parm *pcryp = arg;
    cJSON *json, *chas, *cha, *item; // FIXME: variable names
    int aid, iid;

    json = cJSON_Parse(in);
    chas = cJSON_GetObjectItem(json, "characteristics"); // this is an array
    for (int i=0; i < cJSON_GetArraySize(chas); i++) {
        cha = cJSON_GetArrayItem(chas, i);
        aid = cJSON_GetObjectItem(cha, "aid")->valueint;
        iid = cJSON_GetObjectItem(cha, "iid")->valueint;
        LOG(TRACE, "aid = %d, iid = %d", aid, iid);
        
        item = cJSON_GetObjectItem(cha,"ev");
        if (item) {
            switch (item->type) {
                case cJSON_False:
                    LOG(TRACE, "chas: %d.%d=evF", aid, iid);
                    acc_items[iid].events &= ~pcryp->connectionid;
                    break;

                case cJSON_True:
                    LOG(TRACE, "chas: %d.%d=evT", aid, iid);
                    acc_items[iid].events |= pcryp->connectionid;
                    break;

                default:
                    LOG(TRACE, "chas: %d.%d=evX", aid, iid);
                    break;
            }

            LOG(DEBUG, "events : %02x", acc_items[iid].events)
        }

        item = cJSON_GetObjectItem(cha,"value");
        if (item) {
            LOG_JSON(TRACE, "%08x", acc_items[iid].json, acc_items[iid].json);
            
            // set the value in the master json
            change_value(aid, iid, item);

            LOG_JSON(TRACE, "%08x", acc_items[iid].json, acc_items[iid].json);
                        
            // send out events to subscribed connections
            send_events(pcryp,aid,iid);
            
            // call the callback function if it exists
            if (acc_items[iid].change_cb) {
                acc_items[iid].change_cb(
                    aid,
                    iid,
                    cJSON_GetObjectItem(acc_items[iid].json,"value"),
                    1 // push change
                ); 
            } 
        }
    }

    cJSON_Delete(json);
}

/******************************************************************************
 * FunctionName : check_data
 * Description  : verify if HTTP contentlength is OK
 * Parameters   : precv  -- data to verify
 *                length -- The length of received data
 * Returns      : boolean if OK
*******************************************************************************/
bool ICACHE_FLASH_ATTR
check_data(char *precv, uint16_t length)
{
    char length_buf[10] = {0};
    char *ptemp = NULL;
    char *pdata = NULL;
    char *tmp_precvbuffer;
    uint16 tmp_length = length;
    uint32 tmp_totallength = 0;
    
    ptemp = (char *)strstr(precv, "\r\n\r\n");
    
    if (ptemp != NULL) {
        tmp_length -= ptemp - precv;
        tmp_length -= 4;
        tmp_totallength += tmp_length;
        
        pdata = (char *)strstr(precv, "Content-Length: ");
        
        if (pdata != NULL){
            pdata += 16;
            tmp_precvbuffer = (char *)strstr(pdata, "\r\n");
            
            if (tmp_precvbuffer != NULL){
                memcpy(length_buf, pdata, tmp_precvbuffer - pdata);
                dat_sumlength = atoi(length_buf);
                LOG(DEBUG, "A_dat: %u, tot: %u, lenght: %u", dat_sumlength, tmp_totallength, tmp_length);
                if(dat_sumlength != tmp_totallength){
                    return false;
                }
            }
        }
    }
    return true;
}
