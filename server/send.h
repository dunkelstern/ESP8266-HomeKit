#ifndef server__send_h__included
#define server__send_h__included

typedef void (*acc_cb)(int aid, int iid, cJSON *value, int mode);

typedef struct _acc_item {
    cJSON   *json;
    uint32  events;
    acc_cb  change_cb;
} acc_item;

#define MAXITM 15
extern acc_item acc_items[MAXITM+1];

void change_value(int aid, int iid, cJSON *item);
void send_events(void *arg, int aid, int iid);

void ICACHE_FLASH_ATTR
tlv8_send(void *arg, char *pbuf, uint16_t len);

void ICACHE_FLASH_ATTR
event_send(void *arg, char *psend);

void ICACHE_FLASH_ATTR
h204_send(void *arg);

void ICACHE_FLASH_ATTR
data_send(void *arg, bool responseOK, char *psend);

void ICACHE_FLASH_ATTR
response_send(void *arg, bool responseOK);

void ICACHE_FLASH_ATTR
acc_send(void *arg);

#endif