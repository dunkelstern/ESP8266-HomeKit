
#include <esp_common.h>
#include <espconn.h> // FIXME: separate sending from crypto
#include <cJSON.h>

#include "debug.h"
#include "crypto.h"
#include "send.h"

#include "wolfssl_settings.h"
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/srp.h>
#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/poly1305.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

char B[] = {  //initialize it with value of N
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2,
  0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1,
  0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6,
  0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
  0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
  0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45,
  0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9,
  0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed,
  0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11,
  0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d,
  0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05, 0x98, 0xda, 0x48, 0x36,
  0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f,
  0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56,
  0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d,
  0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04, 0xf1, 0x74, 0x6c, 0x08,
  0xca, 0x18, 0x21, 0x7c, 0x32, 0x90, 0x5e, 0x46, 0x2e, 0x36, 0xce, 0x3b,
  0xe3, 0x9e, 0x77, 0x2c, 0x18, 0x0e, 0x86, 0x03, 0x9b, 0x27, 0x83, 0xa2,
  0xec, 0x07, 0xa2, 0x8f, 0xb5, 0xc5, 0x5d, 0xf0, 0x6f, 0x4c, 0x52, 0xc9,
  0xde, 0x2b, 0xcb, 0xf6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7c,
  0xea, 0x95, 0x6a, 0xe5, 0x15, 0xd2, 0x26, 0x18, 0x98, 0xfa, 0x05, 0x10,
  0x15, 0x72, 0x8e, 0x5a, 0x8a, 0xaa, 0xc4, 0x2d, 0xad, 0x33, 0x17, 0x0d,
  0x04, 0x50, 0x7a, 0x33, 0xa8, 0x55, 0x21, 0xab, 0xdf, 0x1c, 0xba, 0x64,
  0xec, 0xfb, 0x85, 0x04, 0x58, 0xdb, 0xef, 0x0a, 0x8a, 0xea, 0x71, 0x57,
  0x5d, 0x06, 0x0c, 0x7d, 0xb3, 0x97, 0x0f, 0x85, 0xa6, 0xe1, 0xe4, 0xc7,
  0xab, 0xf5, 0xae, 0x8c, 0xdb, 0x09, 0x33, 0xd7, 0x1e, 0x8c, 0x94, 0xe0,
  0x4a, 0x25, 0x61, 0x9d, 0xce, 0xe3, 0xd2, 0x26, 0x1a, 0xd2, 0xee, 0x6b,
  0xf1, 0x2f, 0xfa, 0x06, 0xd9, 0x8a, 0x08, 0x64, 0xd8, 0x76, 0x02, 0x73,
  0x3e, 0xc8, 0x6a, 0x64, 0x52, 0x1f, 0x2b, 0x18, 0x17, 0x7b, 0x20, 0x0c,
  0xbb, 0xe1, 0x17, 0x57, 0x7a, 0x61, 0x5d, 0x6c, 0x77, 0x09, 0x88, 0xc0,
  0xba, 0xd9, 0x46, 0xe2, 0x08, 0xe2, 0x4f, 0xa0, 0x74, 0xe5, 0xab, 0x31,
  0x43, 0xdb, 0x5b, 0xfc, 0xe0, 0xfd, 0x10, 0x8e, 0x4b, 0x82, 0xd1, 0x20,
  0xa9, 0x3a, 0xd2, 0xca, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
uint32_t  B_len = NLEN;

uint16_t objects_maxlen[TLVNUM]= {1,0x50,0,0x180,0x40,0xd0,1,0,0,0,0x40,9}; //global

xQueueHandle crypto_queue;
ed25519_key myKey;

char myUsername[18];
uint16_t myUsername_len = 17;
char myACCname[14]; // accessory name

extern bool pairing;
extern bool halfpaired;
extern Srp srp;

extern void hkc_user_init(char *accname);

void crypto_init() {
    //if already stored then retrieve, else generate and store key
    //also for myUsername
    char flash[80];
    uint32_t sector = 0x13; // FIXME: make flash config sector a constant
    uint32_t start = sector * 0x1000;
    char signature[] = "HomeACcessoryKid";
    WC_RNG rng;
    bool makekey = 1;
    char highuser[9];
    char lowuser[9];
    
    // FIXME: Magic number 4080
    spi_flash_read(start + 4080, (uint32_t *)flash, 16);
    flash[16] = 0;

    HEXDUMP(DEBUG, "Key area flash signature", flash, 16);

    if (strcmp(flash,signature)) {
        LOG(DEBUG, "Initializing key flash");
        spi_flash_erase_sector(sector);
        spi_flash_write(start + 4080, (uint32_t *)signature, 16);
    }
    spi_flash_read(start + 4000, (uint32_t *)flash, 64);

    HEXDUMP(DEBUG, "Key area flash", flash, 64);

    for (uint8_t r = 0; r < 64; r++) {
        if (flash[r]!=0xff) {
            makekey = 0;
            break;
        }
    }
    
    int result = wc_ed25519_init(&myKey);
    if (!result && makekey) {
        result = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &myKey);
        word32 outLen = ED25519_PRV_KEY_SIZE;
        if (result != 0) {
            LOG(ERROR, "Could not make ed25519 key!");
            // FIXME: hang the device?
        }
        
        result = wc_ed25519_export_private(&myKey, flash, &outLen);
        if (result != 0) {
            LOG(ERROR, "Could not export private ed25519 key!");
            // FIXME: hang the device?
        }

        // write the key to flash
        result = spi_flash_write(start + 4000, (uint32_t *)flash, 64);


#if DEBUG_LEVEL <= DEBUG
            spi_flash_read(start + 4000, (uint32_t *)flash, 64);
            HEXDUMP(DEBUG, "key written to flash", flash, 64);
#endif
    } else if (!result) {
        result = wc_ed25519_import_private_key(
            flash,
            ED25519_KEY_SIZE,
            flash + ED25519_KEY_SIZE,
            ED25519_PUB_KEY_SIZE,
            &myKey
        );
        LOG(DEBUG, "key loaded");
    }
    //if an ID stored at position 0 then we are paired already so no need to set up pairing procedures
    //each record is 80 bytes, 12 flag, 36 username, 32 clientPubKey
    pairing = 1;
    spi_flash_read(start, (uint32_t *)flash, 80);
    halfpaired = flash[0] == 0x7f;
    for (uint8_t r = 1; r < 12; r++) {
        if (flash[r] != 0xff) {
            pairing=0;
            break;
        }
    }

    HEXDUMP(DEBUG, "first stored client key", flash, 80);
    LOG(DEBUG, "Pairing: %d", pairing);
    
    // FIXME: this seems out of place
    char mac[6];
    wifi_get_macaddr(STATION_IF, mac);
    sprintf(myUsername, "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    LOG(DEBUG, "Username: %s", myUsername);
}

void crypto_setup1(void *arg) {
    crypto_parm *pcryp = arg;
    char *ptlv8body = NULL;
    uint16 index;
    int r;
    byte salt[16];
    word32 salt_len=16;

    ptlv8body=(char *)zalloc(432); index=0;
    memcpy(salt,srp.salt,salt_len);
    #ifdef DEBUG2
    os_printf("srp pair step 1! Free heap:%d\n", system_get_free_heap_size());
    os_printf("s: "); for (r=0;r<salt_len;r++)os_printf("%02x",salt[r]); os_printf("\n");
    #endif
    tlv8_add(ptlv8body,&index,6,1, "\x02");
    tlv8_add(ptlv8body,&index,2,salt_len,salt);
    tlv8_add(ptlv8body,&index,3,B_len,B);
    tlv8_close(ptlv8body,&index);
    #ifdef DEBUG2
    os_printf("chunked_len: %d\n",index);
    os_printf("Priority:%d\n", uxTaskPriorityGet( NULL ));
    #endif
    tlv8_send(pcryp, ptlv8body, index);
    //now ptlvbody cleaned in tlv8_send but consider doing that here
}

void crypto_setup3(void *arg) {
    crypto_parm *pcryp = arg;
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
    };
    byte proof[SHA512_DIGEST_SIZE];
    word32  proof_len=SHA512_DIGEST_SIZE;
    char *ptlv8body = NULL;
    uint16 index;
    
    ptlv8body=(char *)zalloc(85); index=0;
    #ifdef DEBUG2
    os_printf("srp pair step 3!\r\n");
    os_printf("Free heap:%d\n", system_get_free_heap_size());
    #endif

    int r;
            r = wc_SrpComputeKey(&srp, objects[3], objects_len[3], B, B_len);
    //os_printf("Ckey: %d\n",r);
    
    if (!r) r = wc_SrpVerifyPeersProof(&srp, objects[4], objects_len[4]);
    //os_printf("VPPr: %d\n",r);
    if (!r) r = wc_SrpGetProof(&srp, proof, &proof_len);
    //os_printf("Gprf: %d\n",r);
    #ifdef DEBUG2
    os_printf("key: ");
    for (r=0; r<srp.keySz ; r++) os_printf("%02x",srp.key[r]);
    os_printf("\n");
    #endif
    tlv8_add(ptlv8body,&index,6,1,"\x04");
    tlv8_add(ptlv8body,&index,4,proof_len,proof);
    tlv8_close(ptlv8body,&index);
    #ifdef DEBUG2
    os_printf("chunked_len: %d\n",index);
    #endif
    tlv8_send(pcryp, ptlv8body, index);
    //now ptlvbody cleaned in tlv8_send but consider doing that here
}

void crypto_setup5(void *arg) {
    crypto_parm *pcryp = arg;
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
    };
    ed25519_key     clKey;
    byte encKey[CHACHA20_POLY1305_AEAD_KEYSIZE];
    byte conKey[CHACHA20_POLY1305_AEAD_KEYSIZE];
    byte accKey[CHACHA20_POLY1305_AEAD_KEYSIZE];
    byte esalt[] = "Pair-Setup-Encrypt-Salt";
    word32  esaltSz=23;
    byte einfo[] = "Pair-Setup-Encrypt-Info";
    word32  einfoSz=23;
    byte csalt[] = "Pair-Setup-Controller-Sign-Salt";
    word32  csaltSz=31;
    byte cinfo[] = "Pair-Setup-Controller-Sign-Info";
    word32  cinfoSz=31;
    byte asalt[] = "Pair-Setup-Accessory-Sign-Salt";
    word32  asaltSz=30;
    byte ainfo[] = "Pair-Setup-Accessory-Sign-Info";
    word32  ainfoSz=30;

    char    flash[80];
    uint32  start, sector = 0x13;
    start=sector*0x1000;
    
    char *ptlv8body = NULL;
    uint16 index;
    int verified;
    byte nonce[]= "0000PS-Msg05"; //needs to be 12 bytes, will prepad with 0000s
    
    nonce[0]=0; nonce[1]=0;nonce[2]=0;nonce[3]=0; //padding the first four bytes
    ptlv8body=(char *)zalloc(180); index=0;  //tune size
    #ifdef DEBUG2
    os_printf("srp pair step 5!\r\n");
    os_printf("Free heap:%d\n", system_get_free_heap_size());
    #endif
    
    int r;
            r = wc_HKDF(SHA512, srp.key, srp.keySz, esalt, esaltSz, einfo, einfoSz,
                        encKey, CHACHA20_POLY1305_AEAD_KEYSIZE);
    #ifdef DEBUG2
    os_printf("encKey%d:",r);
    for (r=0; r< CHACHA20_POLY1305_AEAD_KEYSIZE ; r++) os_printf("%02x",encKey[r]);
    os_printf("\n");
    #endif
    r=0;
    if (!r) r = wc_ChaCha20Poly1305_Decrypt(encKey, nonce, NULL, 0, 
                objects[5], objects_len[5]-16, objects[5]+objects_len[5]-16, ptlv8body);
    if (!r) tlv8_parse(ptlv8body,objects_len[5]-16,objects,objects_len); 
    
    /*******************************************************************/
    
    byte    myLTPK[ED25519_PUB_KEY_SIZE];
    word32  myLTPK_len=ED25519_PUB_KEY_SIZE;
    r = wc_ed25519_export_public(&myKey, myLTPK, &myLTPK_len);
    #ifdef DEBUG2
    os_printf("myLTPK: "); for (r=0;r<myLTPK_len;r++) os_printf("%02x",myLTPK[r]); os_printf("\n");
    #endif
    //clientLTPK key should be imported for usage
            r = wc_ed25519_init(&clKey);
            r = wc_ed25519_import_public(objects[3], objects_len[3], &clKey);
    
    /****** verify clients ed25519 signature  ***************************/
    r = wc_HKDF(SHA512, srp.key, srp.keySz, csalt, csaltSz, cinfo, cinfoSz, conKey, 32);
    //concat conKey, objects[1], objects[3]  and (ab)use objects[5] for storage
    memcpy(objects[5]               ,conKey    ,32            ); objects_len[5]=32;
    memcpy(objects[5]+objects_len[5],objects[1],objects_len[1]); objects_len[5]+=objects_len[1];
    memcpy(objects[5]+objects_len[5],objects[3],objects_len[3]); objects_len[5]+=objects_len[3];
    
    //ed25519.Verify(concat, clientProof[10], clientLTPK[3])
    r = wc_ed25519_verify_msg(objects[10], objects_len[10], objects[5],objects_len[5], &verified, &clKey);
    #ifdef DEBUG0
    os_printf("verified=%d r=%d\n",verified,r);
    #endif
    //stop mDNS advertising and store that decision?
    
    if (verified && !halfpaired) { //prevent double writing
        #ifdef DEBUG2
        spi_flash_read(start,(uint32 *)flash,80);
        for (r=0;r<80;r++) os_printf("%02x",flash[r]);os_printf("\n");
        #endif
        flash[0]=0x7f;
        memset(flash+1,0xff,11); //flag first 12 bytes to 01111111111...1111
        memcpy(flash+12,               objects[1],objects_len[1]); //client userName
        memcpy(flash+12+objects_len[1],objects[3],objects_len[3]); //clientLTPK
        #ifdef DEBUG0
        os_printf("writing paired client to flash\n");
        #endif
        spi_flash_write(start,(uint32 *)flash,80);
        halfpaired=1;
        #ifdef DEBUG2
        spi_flash_read(start,(uint32 *)flash,80);
        for (r=0;r<80;r++) os_printf("%02x",flash[r]);os_printf("\n");
        #endif
    }
    // else send 7/1/2
    /******** sign my own part ********************************************/
    r = wc_HKDF(SHA512, srp.key, srp.keySz, asalt, asaltSz, ainfo, ainfoSz, accKey, 32);
    //concat accKey, myUserName, myLTPK  and (ab)use objects[5] for storage
    memcpy(objects[5]               ,accKey    ,32            ); objects_len[5]=32;
    memcpy(objects[5]+objects_len[5],myUsername,myUsername_len); objects_len[5]+=myUsername_len;
    memcpy(objects[5]+objects_len[5],myLTPK    ,myLTPK_len    ); objects_len[5]+=myLTPK_len    ;
    //sign this and use objects[10] for proof storage
    uint32_t len = objects_maxlen[10];
    r = wc_ed25519_sign_msg(objects[5], (uint32_t)objects_len[5], objects[10], &len, &myKey);
    objects_len[10] = len;
    //fill ptlv8body again with concatenated items 1, 3 and 10 in tlv8 style
    index=0; ptlv8body[index++]=1;   ptlv8body[index++]=myUsername_len;
    for (r=0; r<myUsername_len;r++)  ptlv8body[index++]=myUsername[r];
    ptlv8body[index++]=3;            ptlv8body[index++]=myLTPK_len;
    for (r=0; r<myLTPK_len;r++)      ptlv8body[index++]=myLTPK[r];
    ptlv8body[index++]=10;           ptlv8body[index++]=objects_len[10];
    for (r=0; r<objects_len[10];r++) ptlv8body[index++]=objects[10][r];
    // encrypt this and (ab)use objects[5] for storage
    nonce[11]=0x36; //turn it into "0000PS-Msg06"
    objects_len[5]=index+16;
    r = wc_ChaCha20Poly1305_Encrypt(encKey, nonce, NULL, 0, 
                                    ptlv8body, index, objects[5], objects[5]+index);
    //tlv8 encode
    index=0;
    tlv8_add(ptlv8body,&index,6,1,"\x06");
    tlv8_add(ptlv8body,&index,5,objects_len[5],objects[5]);
    tlv8_close(ptlv8body,&index);
    #ifdef DEBUG2
    os_printf("chunked_len: %d\n",index);
    #endif
    //clean up and start json_init before answer
    //wc_SrpTerm(&srp); // also get rid of B and make srp a dynamic memory
    
#if 1
    hkc_user_init(myACCname); // FIXME: shouldn't this create the json task?
#else    
    xTaskCreate(json_init, "jinit", 2560, NULL, 1, NULL);
#endif

    tlv8_send(pcryp, ptlv8body, index);
    //now ptlvbody cleaned in tlv8_send but consider doing that here
//  if (! pairing) {
//      os_delay_us(0xffff); //allow some time to send confirmation to client
//      system_restart();
//      os_printf("this should not be seen after a pair reset\n");
//  }
}

void crypto_verify1(void *arg) {
    crypto_parm *pcryp = arg;
    uint16_t *objects_len=pcryp->objects_len;
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
    };
    curve25519_key  mycurvekey;
    curve25519_key  clcurvekey;
    WC_RNG rng;
    byte esalt[] = "Pair-Verify-Encrypt-Salt";
    word32  esaltSz=24;
    byte einfo[] = "Pair-Verify-Encrypt-Info";
    word32  einfoSz=24;
    uint32  oldsystime;

    char *ptlv8body = NULL;
    uint16 index;
    byte nonce[]= "0000PV-Msg02"; //needs to be 12 bytes, will prepad with 0000s
    
    nonce[0]=0; nonce[1]=0;nonce[2]=0;nonce[3]=0; //padding the first four bytes

    #ifdef DEBUG2
    os_printf("pair verify step 1 at %d\r\n",system_get_time()/1000);
    os_printf("Free heap:%d\n", system_get_free_heap_size());
    #endif
    ptlv8body=(char *)zalloc(162); index=0;  //verify number

    int r;
            r = wc_curve25519_init(&clcurvekey);
    if (!r) r = wc_curve25519_init(&mycurvekey);    
    if (!r) r = wc_curve25519_make_key(&rng, 32, &mycurvekey);
    uint32_t len = objects_maxlen[5];
    if (!r) r = wc_curve25519_export_public_ex(&mycurvekey, objects[5], &len, EC25519_LITTLE_ENDIAN);
    objects_len[5] = len;
    #ifdef DEBUG2
    os_printf("mycurvekey: ");
    for (r=0; r<objects_len[5] ; r++) os_printf("%02x",objects[5][r]);
    os_printf("\nclcurvekey: ");
    for (r=0; r<objects_len[3] ; r++) os_printf("%02x",objects[3][r]);
    os_printf("\n");
    #endif
    memcpy(pcryp->readKey, objects[3],32); //transfer clcurvekey to verify3step
    memcpy(pcryp->writeKey,objects[5],32); //transfer mycurvekey to verify3step
            r = wc_curve25519_import_public_ex(objects[3], objects_len[3], &clcurvekey, EC25519_LITTLE_ENDIAN);
    pcryp->sessionkey_len = 32;
    oldsystime=system_get_time()/1000;
    #ifdef DEBUG2
    os_printf("system time: %d\n",oldsystime);
    #endif
    if (!r) r = wc_curve25519_shared_secret_ex(&mycurvekey, &clcurvekey, pcryp->sessionkey, &pcryp->sessionkey_len, EC25519_LITTLE_ENDIAN);
    #ifdef DEBUG0
    os_printf("shared secret time: %d\n",(system_get_time()/1000)-oldsystime);
    #endif
    #ifdef DEBUG2
    os_printf("sessionkey: ");
    for (r=0; r<pcryp->sessionkey_len; r++) os_printf("%02x",pcryp->sessionkey[r]);
    os_printf("\n");
    #endif

    // prepare answer5  var material = Buffer.concat([publicKey,usernameData,clientPublicKey]);
    // obj5 = obj5 + myUsername + obj3
    memcpy(objects[5]+objects_len[5],myUsername,myUsername_len); objects_len[5]+=myUsername_len;
    memcpy(objects[5]+objects_len[5],objects[3],objects_len[3]); objects_len[5]+=objects_len[3];
    // transfer my public curve key to objects[3] (client pub curve key not needed anymore)
    len = objects_maxlen[3];
    r = wc_curve25519_export_public_ex(&mycurvekey, objects[3], &len, EC25519_LITTLE_ENDIAN);
    objects_len[3] = len;
    //sign object5 and use objects[10] for proof storage
    objects_len[10]=objects_maxlen[10];
    oldsystime=system_get_time()/1000;
    #ifdef DEBUG2
    os_printf("system time: %d\n",oldsystime);
    #endif
    len = objects_len[10];
    r = wc_ed25519_sign_msg(objects[5], objects_len[5], objects[10], &len, &myKey);
    objects_len[10] = len;
    #ifdef DEBUG0
    os_printf("sign message time: %d\n",(system_get_time()/1000)-oldsystime);
    #endif
    #ifdef DEBUG2
    os_printf("edsign: %d\n",r);
    os_printf("system time: %d\n",system_get_time()/1000);
    #endif

    if (!r) r = wc_HKDF(SHA512, pcryp->sessionkey, pcryp->sessionkey_len, esalt, esaltSz, einfo, einfoSz, pcryp->verKey, 32);
    
    //fill ptlv8body again with concatenated items 1 and 10 in tlv8 style
    index=0; ptlv8body[index++]=1;   ptlv8body[index++]=myUsername_len;
    for (r=0; r<myUsername_len;r++)  ptlv8body[index++]=myUsername[r];
    ptlv8body[index++]=10;           ptlv8body[index++]=objects_len[10];
    for (r=0; r<objects_len[10];r++) ptlv8body[index++]=objects[10][r];
    // encrypt this and (ab)use objects[5] for storage
    objects_len[5]=index+16;
    r = wc_ChaCha20Poly1305_Encrypt(pcryp->verKey, nonce, NULL, 0, 
                                    ptlv8body, index, objects[5], objects[5]+index);
    // tlv8 encode
    index=0;
    tlv8_add(ptlv8body,&index,6,1,"\x02");
    tlv8_add(ptlv8body,&index,5,objects_len[5],objects[5]);
    tlv8_add(ptlv8body,&index,3,objects_len[3],objects[3]);
    tlv8_close(ptlv8body,&index);
    #ifdef DEBUG2
    os_printf("chunked_len: %d\n",index);
    #endif
    tlv8_send(pcryp, ptlv8body, index);
    //now ptlvbody cleaned in tlv8_send but consider doing that here
}

void crypto_verify3(void *arg) {
    crypto_parm *pcryp = arg;
    uint16_t *objects_len=pcryp->objects_len;
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
    };
    ed25519_key     clKey;

    char *ptlv8body = NULL;
    uint16 index;
    int verified;
    int shallencrypt=0;
    int found=0;
    int part,k;
    char    flash[80];
    uint32  start, sector = 0x13;
    start=sector*0x1000;

    byte rwsalt[]= "Control-Salt";
    word32  rwsaltSz=12;
    byte rinfo[] = "Control-Read-Encryption-Key";
    word32  rinfoSz=27;
    byte winfo[] = "Control-Write-Encryption-Key";
    word32  winfoSz=28;
    uint32  oldsystime;

    byte nonce[]= "0000PV-Msg03"; //needs to be 12 bytes, will prepad with 0000s
    
    nonce[0]=0; nonce[1]=0;nonce[2]=0;nonce[3]=0; //padding the first four bytes
    
    #ifdef DEBUG2
    os_printf("pair verify step 3 at %d\r\n",system_get_time()/1000);
    os_printf("Free heap:%d\n", system_get_free_heap_size());
    #endif
    ptlv8body=(char *)zalloc(160); index=0;  //verify number 110?
    
    int r=0;
    
    if (!r) r = wc_ChaCha20Poly1305_Decrypt(pcryp->verKey, nonce, NULL, 0, 
                    objects[5], objects_len[5]-16, objects[5]+objects_len[5]-16, ptlv8body);
    if (!r)     tlv8_parse(ptlv8body,objects_len[5]-16,objects,objects_len);
    
    //collect clientLTPK from flash and import it in clKey (overwrite previous sessions key)
    for (k=0;k<50;k++) {  //maximum 50 slots
        spi_flash_read(start+k*80,(uint32 *)flash,80);
        #ifdef DEBUG2
        for (r=12;r<48;r++) os_printf("%c",flash[r]);os_printf(" -- ");
        for (r=0;r<80;r++) os_printf("%02x",flash[r]);os_printf("\n");
        #endif
        if (flash[0]==0xff) break; //never used slot
        //if flag is active key then use, else continue
        part=0; while (!flash[part+1] && part<12) part+=2;
        if (flash[part]==flash[part+1]) continue; //inactive slot
        //compare to objects[1] = client user name else continue
        if (memcmp(flash+12,objects[1],36)) continue;
                r = wc_ed25519_init(&clKey);
                r = wc_ed25519_import_public(flash+12+36,ED25519_PUB_KEY_SIZE,&clKey);
        #ifdef DEBUG0
        os_printf("key %d loaded - result: %d\n",k,r);
        #endif
        found=1;
        break;
    }
    if (found) {
        memcpy(objects[5]               ,pcryp->readKey   ,32            ); objects_len[5]=32;  //clcurvekey
        memcpy(objects[5]+objects_len[5],objects[1],objects_len[1]); objects_len[5]+=objects_len[1];
        memcpy(objects[5]+objects_len[5],pcryp->writeKey  ,32            ); objects_len[5]+=32; //mycurvekey
        #ifdef DEBUG2
        os_printf("system time: %d\n",system_get_time()/1000);
        #endif
    
        //ed25519.Verify(concat, clientProof[10], clKey[3])
        oldsystime=system_get_time()/1000;
        #ifdef DEBUG2
        os_printf("system time: %d\n",oldsystime);
        #endif
        r = wc_ed25519_verify_msg(objects[10], objects_len[10], objects[5],objects_len[5], &verified, &clKey);
        #ifdef DEBUG0
        os_printf("verify message time: %d, ",(system_get_time()/1000)-oldsystime);
        os_printf("verified=%d r=%d\n",verified,r);
        #endif
        // else send 7/1/2

        if ( verified==1 ) {
            tlv8_add(ptlv8body,&index,6,1,"\x04");
            shallencrypt=1;
            //prepare keys
//          #ifdef DEBUG2
//          os_printf("sessionkey: ");
//          for (r=0; r<pcryp->sessionkey_len; r++) os_printf("%02x",pcryp->sessionkey[r]);
//          os_printf("\n");
//          #endif
                    r = wc_HKDF(SHA512, pcryp->sessionkey, pcryp->sessionkey_len, rwsalt, rwsaltSz, rinfo, rinfoSz, pcryp->readKey,  32);
            if (!r) r = wc_HKDF(SHA512, pcryp->sessionkey, pcryp->sessionkey_len, rwsalt, rwsaltSz, winfo, winfoSz, pcryp->writeKey, 32);
        } else tlv8_add(ptlv8body,&index,7,1, "\x04"); //verification failed
    } else tlv8_add(ptlv8body,&index,7,1, "\x02"); //clientLTPK not found

    tlv8_close(ptlv8body,&index);
    #ifdef DEBUG2
    os_printf("chunked_len: %d\n",index);
    #endif
    tlv8_send(pcryp, ptlv8body, index);
    if (shallencrypt)   pcryp->encrypted=1; //else too early if this answer also gets encrypted
    //now ptlvbody cleaned in tlv8_send but consider doing that here
}

// length will change! 
void decrypt(void *arg, char *data, unsigned short *length) {
    crypto_parm *pcryp = arg;
    int r,total,offset,len;
    byte *buffer = NULL;

    byte nonce[12]={0,0,0,0,0,0,0,0,0,0,0,0};
    #ifdef DEBUG2
    os_printf("raw: ");
    for (r=0;r<*length;r++) os_printf("%02x",data[r]);
    os_printf("\n");/**/
    #endif
    //do decryption things and result is in data again

    buffer = (byte *)zalloc(*length);
    total=*length; *length=0;
    for (offset=0;offset<total;){
        len = 255*data[1]+data[0]; //Little Endian
        nonce[4]=pcryp->countwr%256;nonce[5]=pcryp->countwr++/256; //should fix to grow beyond 64k but not urgent
        #ifdef DEBUG2
        os_printf("nonce %02x %02x\n",nonce[4],nonce[5]);
        #endif
        r = wc_ChaCha20Poly1305_Decrypt(pcryp->writeKey, nonce, data+offset, 2, 
                        data+offset+2, len, data+offset+2+len, buffer);
        for (r=0;r<len;r++) data[r+*length]=buffer[r];
        *length+=len; offset+=len+0x12;
    }
    #ifdef DEBUG0
    //os_printf("txt:\n");
    for (r=0;r<*length;r++) os_printf("%c",data[r]);
    os_printf("\n");
    #endif
    #ifdef DEBUG2
/*  os_printf("dec: ");
    for (r=0;r<*length;r++) os_printf("%02x",data[r]);
    os_printf("\n");/**/
    os_printf("Free heap:%d\n", system_get_free_heap_size());/**/
    #endif

    free(buffer);
}

void encrypt(void *arg, char *data, unsigned short *length) {
    crypto_parm *pcryp = arg;
    int r,total,offset,len;
    byte *in = NULL;
    byte nonce[12]={0,0,0,0,0,0,0,0,0,0,0,0};
    char    lelen[2];
    
    in = (byte *)zalloc(*length);
    memcpy(in, data, *length);
    //os_printf("system time: %d\n",system_get_time()/1000);
    #ifdef DEBUG0
    //os_printf("txt: ");
    for (r=0;r<*length;r++) os_printf("%c",in[r]);
    os_printf("\n"); /**/
    #endif
    //os_printf("system time: %d\n",system_get_time()/1000);
    #ifdef DEBUG2
    os_printf("length: 0x%04x\n",*length);
    #endif

    total=*length; *length=0;
    for (offset=0;offset<total;){
        len=total-offset; len = (len<0x400)?len:0x400; lelen[0]=len%256; lelen[1]=len/256;
        nonce[4]=pcryp->countrd%256;nonce[5]=pcryp->countrd++/256; //should fix to grow beyond 64k but not urgent
        #ifdef DEBUG2
        os_printf("nonce %02x %02x\n",nonce[4],nonce[5]);
        #endif
        memcpy(data+*length,lelen,2);
        r = wc_ChaCha20Poly1305_Encrypt(pcryp->readKey, nonce, lelen, 2, 
                    in+offset, len, data+*length+2, data+*length+2+len);
        *length+=len+0x12; offset+=len;
    }

    free(in);
}
