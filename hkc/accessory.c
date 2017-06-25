#include "debug.h"
#include "accessory.h"

#include <send.h> // FIXME: acc items should not be defined there

cJSON *root;

extern void hkc_user_init(char *accname);
extern char myACCname[14];
extern bool ready;

void ICACHE_FLASH_ATTR
json_init(void *arg) {
    hkc_user_init(myACCname);
    ready = 1;

    LOG(DEBUG, "ready @ %d", system_get_time() / 1000);
    vTaskDelete(NULL);
}

cJSON * ICACHE_FLASH_ATTR
initAccessories() {
    cJSON   *accs;
    
    memset(acc_items,0,sizeof(acc_items));
    root=cJSON_CreateObject();
    cJSON_AddItemToObject( root, "accessories", accs=cJSON_CreateArray());

    return accs;
}

cJSON * ICACHE_FLASH_ATTR
addAccessory(cJSON *accs, int aid) {
    cJSON *acc,*sers;
    
    cJSON_AddItemToArray(accs,acc=cJSON_CreateObject());
    cJSON_AddNumberToObject(acc, "aid",  aid );
    cJSON_AddItemToObject(  acc, "services", sers=cJSON_CreateArray());
    
    return sers;
}

cJSON * ICACHE_FLASH_ATTR
addService(cJSON *services, int iid, char *brand, int sType) {
    cJSON *service,*characteristics;
    char longid[37];
    
    sprintf(longid,brand,sType);
    cJSON_AddItemToArray(services,service=cJSON_CreateObject());
    cJSON_AddNumberToObject(service, "iid",  iid );
    cJSON_AddStringToObject(service, "type", longid  );
    cJSON_AddItemToObject(  service, "characteristics", characteristics=cJSON_CreateArray());
    
    return characteristics;
}

void ICACHE_FLASH_ATTR
addCharacteristic(cJSON *characteristics, int aid, int iid, char *brand, int cType, char *valuestring, acc_cb change_cb) {
    cJSON *perms,*value=NULL;
    char longid[37],format[7];
    int perm, maxlen, intval, ev=0;
    
    sprintf(longid,brand,cType);
    cJSON_AddItemToArray(   characteristics,acc_items[iid].json=cJSON_CreateObject());
    cJSON_AddNumberToObject(acc_items[iid].json, "iid",  iid );
    cJSON_AddStringToObject(acc_items[iid].json, "type", longid  );
    cJSON_AddItemToObject(  acc_items[iid].json, "perms", perms=cJSON_CreateArray());
    cJSON_AddFalseToObject( acc_items[iid].json, "bonjour");
    //from id pick up specific settings
    switch (cType) {
        case IDENTIFY_C: {
            strcpy(format,BOOLEAN);     perm=2;     maxlen=1;
            cJSON_AddStringToObject(acc_items[iid].json, "description", "Identify");
        } break;
        case MANUFACTURER_C: {
            strcpy(format,STRING);      perm=4;     maxlen=255;
            cJSON_AddStringToObject(acc_items[iid].json, "description", "Manufacturer");
        } break;
        case MODEL_C: {
            strcpy(format,STRING);      perm=4;     maxlen=255;
            cJSON_AddStringToObject(acc_items[iid].json, "description", "Model");
        } break;
        case SERIAL_NUMBER_C: {
            strcpy(format,STRING);      perm=4;     maxlen=255;
            cJSON_AddStringToObject(acc_items[iid].json, "description", "Serial");
        } break;
        case NAME_C: {
            strcpy(format,STRING);      perm=4;     maxlen=255;
            cJSON_AddStringToObject(acc_items[iid].json, "description", "Name");
        } break;
        case POWER_STATE_C: {
            strcpy(format,BOOLEAN);     perm=7;     maxlen=1;   ev=1;
            cJSON_AddStringToObject(acc_items[iid].json, "description", "PowerState");
        } break;
        case BRIGHTNESS_C: {
            strcpy(format,INT);         perm=7;     maxlen=0;   ev=1;
            cJSON_AddStringToObject(acc_items[iid].json, "description", "Brightness");
            cJSON_AddNumberToObject(acc_items[iid].json, "minValue",   0);
            cJSON_AddNumberToObject(acc_items[iid].json, "maxValue", 100);
            cJSON_AddNumberToObject(acc_items[iid].json, "minStep",    5);
            cJSON_AddStringToObject(acc_items[iid].json, "unit", "%");
        } break;
        default: {
            
        } break;
    }
    if (ev) cJSON_AddTrueToObject( acc_items[iid].json, "events");
    else    cJSON_AddFalseToObject(acc_items[iid].json, "events");
    cJSON_AddStringToObject(acc_items[iid].json, "format", format);
    if (maxlen) cJSON_AddNumberToObject(acc_items[iid].json, "maxLen", maxlen );
    //encode perms like rwe octal
    if (perm & 2) cJSON_AddItemToArray(perms,cJSON_CreateString("pw"));
    if (perm & 4) cJSON_AddItemToArray(perms,cJSON_CreateString("pr"));
    if (perm & 1) cJSON_AddItemToArray(perms,cJSON_CreateString("ev"));
    //addItem(aid,iid,format,valuestring,change_cb);
    if (valuestring) {
        if (!strcmp(format,BOOLEAN)){
            if ( !strcmp(valuestring,"0") || !strcmp(valuestring,"false") ) intval=0; else intval=1;
            cJSON_AddItemToObject(acc_items[iid].json, "value", value=cJSON_CreateBool(intval) );
        }
        if (!strcmp(format,STRING)){
            cJSON_AddItemToObject(acc_items[iid].json, "value", value=cJSON_CreateString(valuestring) );
        }
        if (!strcmp(format,INT)){
            cJSON_AddItemToObject(acc_items[iid].json, "value", value=cJSON_CreateNumber(atoi(valuestring)) );
        }
    }
    acc_items[iid].change_cb= (acc_cb) change_cb;
    if (change_cb) change_cb(aid,iid,value,0); //0 is initialize
}
