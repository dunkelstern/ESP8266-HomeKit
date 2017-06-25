#include <esp_common.h>
#include <cJSON.h>

#include "debug.h"

#include "crypto.h"
#include "tlv8.h" // FIXME: does this have to be spaghettied in?
#include "send.h" // FIXME: does this have to be spaghettied in?

bool pairing = 0;
bool halfpaired = 0;

void pairadd(void *arg) {
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
    char *ptlv8body = (char *)zalloc(16);
    uint16_t index = 0;
    int part;
    bool found = 0;
    char flash[80];
    uint32_t sector = 0x13; // FIXME: make constant somewhere
    uint32_t start = sector * 0x1000;
    uint8_t k;

    LOG_HEAP("pair add");

    // FIXME: make number of slots a define or constant
    for (k = 1; k < 50; k++) {  //maximum 50 slots first one reserved for paired device, rest for guests
        // FIXME: magic number 80
        spi_flash_read(start + k * 80, (uint32_t *) flash, 80); //find if it exists or where list ends
        if (flash[0] == 0xff){
            break; //never used slot
        }

#if DEBUG_LEVEL <= DEBUG
        for (uint8_t r = 12; r < 48; r++) {
            os_printf("%c", flash[r]);
        }
        os_printf(" -- ");

        for (uint8_t r = 0; r < 80; r++) {
            os_printf("%02x", flash[r]);
        }
        os_printf("\n");
#endif
        //compare to objects[1] else continue
        if (memcmp(flash + 12, objects[1], 36)) {
            continue;
        }

        found = 1; // FIXME: compare key to make sure it is the same??
        
        //if flag is active key then nothing, else activate it
        part = 0;
        while (!flash[part + 1] && part < 12) {
            part += 2;
        }

        if (flash[part] == flash[part + 1]) { //inactive slot
            if (!flash[part + 1]) { //right part is zero
                if (part == 10) {
                    found = 0;
                    continue; //no more space, look for new slot
                } else {
                    part += 2;
                }
            } //need to move to next bytes

            flash[part] /= 2; //sets left bit to zero?
            LOG(DEBUG, "key %d: writing flag to flash", k);

            spi_flash_write(start + k * 80, (uint32_t *)flash, 12);
        } //else nothing because flag already active
    }
    
    if (!found) {
        if (k == 50) {
            LOG(DEBUG, "no more space");
        } else {
            flash[0] = 0x7f;
            memset(flash + 1, 0xff, 11); //flag first 12 bytes to 01111111111...1111
            memcpy(flash + 12, objects[1], objects_len[1]);
            memcpy(flash + 12 + objects_len[1], objects[3], objects_len[3]);
            HEXDUMP(DEBUG, "writing client to flash", flash, 80);
            spi_flash_write(start + k * 80, (uint32_t *)flash, 80);
        }
    }

    tlv8_add(ptlv8body, &index, 6, 1, "\x02");
    tlv8_close(ptlv8body, &index);
    LOG(TRACE, "chunked_len: %d", index);
    tlv8_send(pcryp, ptlv8body, index);  //we need to encrypt this!
    //now ptlvbody cleaned in tlv8_send but consider doing that here
}

void pairdel(void *arg) {
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
    char *ptlv8body = (char *)zalloc(16);
    uint16 index = 0;
    int part;
    bool found = 0;
    char flash[80];
    uint32_t sector = 0x13;
    uint32_t start = sector * 0x1000;
    
    LOG_HEAP("pair del");

    //if this refers to position 0 then unpair and reset
    pairing = 0;  //verify if this is correct!!
    //kill signature in flash and reset device

    for (uint8_t k = 0; k < 50; k++) {  //maximum 50 slots first one reserved for paired device, rest for guests
        spi_flash_read(start + k * 80, (uint32_t *)flash, 80); //find if it exists or where list ends
        if (flash[0] == 0xff) {
            break; //never used slot
        }

#if DEBUG_LEVEL <= DEBUG
        for (uint8_t r = 12; r < 48; r++) {
            os_printf("%c", flash[r]);
        }
        os_printf(" -- ");

        for (uint8_t r = 0; r < 80; r++) {
            os_printf("%02x", flash[r]);
        }
        os_printf("\n");
#endif
        //compare to objects[1] else continue
        if (memcmp(flash + 12, objects[1], 36)) {
            continue;
        }

        found = 1;
        if (k == 0) { //this is an unpair activity
            LOG(TRACE, "unpair mutilate signature and reset");
            spi_flash_write(start + 4080, (uint32_t *)flash + 12, 16); //mutilate the signature

#if DEBUG_LEVEL <= DEBUG
            //did it work?
            spi_flash_read(start + 4080, (uint32_t *)flash, 16);             
            HEXDUMP(DEBUG, "removed client from flash", flash, 16);
#endif
            pairing = 1; //this will trigger the reset
            break;
        }

        //if flag is inactive key then nothing, else deactivate it
        part=0;
        while (!flash[part + 1] && part < 12) {
            part+=2;
        }

        if (flash[part + 1] != flash[part]) { //active slot
            flash[part + 1] = flash[part];  //sets left bit to zero?
            LOG(TRACE, "key %d, writing flag to flash",k);
            spi_flash_write(start + k * 80,(uint32_t *)flash, 12);
        } //else nothing because flag already inactive
    }
    
    tlv8_add(ptlv8body, &index, 6, 1, "\x02");
    tlv8_close(ptlv8body, &index);
    LOG(TRACE, "chunked_len: %d\n", index);
    tlv8_send(pcryp, ptlv8body, index);

    //now ptlvbody cleaned in tlv8_send but consider doing that here
    if (pairing) {
        // FIXME: what is this even?!?
        os_delay_us(0xffff); //allow some time to send confirmation to client?
        system_restart();
    }
}
