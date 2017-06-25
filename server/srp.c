#include "debug.h"
#include "srp.h"
#include "crypto.h"

#define WOLFSSL_SHA512
#define NO_MD5
#define NO_SHA
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>

extern char B[];
extern uint32_t  B_len;
bool ready;

Srp srp;

//HacK the function as chosen by Apple is just the hash of the secret
// FIXME: can this be static???
int wc_SrpSetKeyH(Srp *srp, byte *secret, word32 size) {
    SrpHash hash;
    int r = BAD_FUNC_ARG;

    srp->key = (byte*)XMALLOC(SHA512_DIGEST_SIZE, NULL, DYNAMIC_TYPE_SRP);
    if (srp->key == NULL)
        return MEMORY_E;

    srp->keySz = SHA512_DIGEST_SIZE;

    r = wc_InitSha512(&hash.data.sha512);
    if (!r) r = wc_Sha512Update(&hash.data.sha512, secret, size);
    if (!r) r = wc_Sha512Final(&hash.data.sha512, srp->key);

    //ForceZero(&hash, sizeof(SrpHash));
    memset(&hash,0,sizeof(SrpHash));

    return r;
}

void srp_prepare() {
    int r;
    char g[]={0x05};
    uint32_t g_len=1;
    char salt[16];
    uint32_t salt_len=16;
    char b[32];
    uint32_t b_len=32;   

    
    LOG(DEBUG, "system time: %d", system_get_time() / 1000);
    r = os_get_random((unsigned char *)salt, salt_len);
    r = os_get_random((unsigned char *)b, b_len);
    
    HEXDUMP(DEBUG, "Salt", salt, salt_len);
    HEXDUMP(DEBUG, "B", b, b_len);
    r = wc_SrpInit(&srp, SRP_TYPE_SHA512, SRP_CLIENT_SIDE);
    srp.keyGenFunc_cb = wc_SrpSetKeyH;
    if (!r) r = wc_SrpSetUsername(&srp, "Pair-Setup", 10);
    if (!r) r = wc_SrpSetParams(&srp, (const byte *)B, NLEN, g, g_len, salt, salt_len);
    if (!r) r = wc_SrpSetPassword(&srp, PASSWORD, PASSWORD_LEN);
    if (!r) r = wc_SrpGetVerifier(&srp, (byte *)B, &B_len); //use B to store v
    
    srp.side = SRP_SERVER_SIDE; //switch to server mode
    if (!r) r = wc_SrpSetVerifier(&srp, (const byte *)B, B_len); //used B to store v
    if (!r) r = wc_SrpSetPrivate(&srp, b, b_len);
    if (!r) r = wc_SrpGetPublic(&srp, (byte *)B, &B_len);

#if DEBUG_LEVEL <= DEBUG
    //print stack high water mark
    char report[500];
    vTaskList(report);
    printf(report);
#endif

    LOG(DEBUG, "srp key generated, system time: %d", system_get_time() / 1000);
    HEXDUMP(DEBUG, "srp key", B, NLEN);

    // FIXME: signal instead of ready flag
    ready = 1; //this unlocks the mdns messages and server
    vTaskDelete(NULL); // remove this task
}
