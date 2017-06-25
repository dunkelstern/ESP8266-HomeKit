#ifndef server__crypto_h__included
#define server__crypto_h__included

#include <esp_common.h>
#include <freertos/semphr.h>

#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_ED25519
#define HAVE_CURVE25519
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>

#include "tlv8.h"

extern xQueueHandle crypto_queue;
#define NLEN 384

typedef struct _crypto_parm {
    xSemaphoreHandle semaphore;
    struct espconn  *pespconn;
    int             state;
    int             stale;
    uint32_t        connectionid;
    int             encrypted;
    long            countwr;
    long            countrd;
    uint32_t        sessionkey_len;
    char            sessionkey[32];
    char            verKey[CHACHA20_POLY1305_AEAD_KEYSIZE];
    char            readKey[CHACHA20_POLY1305_AEAD_KEYSIZE];
    char            writeKey[CHACHA20_POLY1305_AEAD_KEYSIZE];
    char            object[0x1cb];
    uint16_t        objects_len[TLVNUM];
} crypto_parm;

void crypto_tasks();
void crypto_init();
void crypto_setup1(void *arg);
void crypto_setup3(void *arg);
void crypto_setup5(void *arg);
void crypto_verify1(void *arg);
void crypto_verify3(void *arg);
void decrypt(void *arg, char *data, unsigned short *length);
void encrypt(void *arg, char *data, unsigned short *length);
#endif