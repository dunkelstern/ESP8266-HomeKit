#include <esp_common.h>
#include <espconn.h>
#include <cJSON.h>

#include "debug.h"
#include "esp_reverse_engineered.h"
#include "server.h"
#include "crypto.h"
#include "send.h"
#include "recv.h"
#include "pairing.h"

extern espconn_msg *plink_active;
os_timer_t  browse_timer;
xSemaphoreHandle cid_semaphore;
struct espconn hkcesp_conn;

/******************************************************************************
 * FunctionName : server_sent
 * Description  : a packet has been sent
 * Parameters   : arg -- Additional argument to pass to the callback function
 * Returns      : none
*******************************************************************************/
LOCAL ICACHE_FLASH_ATTR
void server_sent(void *arg) {
    struct espconn *pesp_conn = arg;

    LOG(TRACE, "server sent a packet to %d.%d.%d.%d:%d at %d",
        pesp_conn->proto.tcp->remote_ip[0],
        pesp_conn->proto.tcp->remote_ip[1],
        pesp_conn->proto.tcp->remote_ip[2],
        pesp_conn->proto.tcp->remote_ip[3],
        pesp_conn->proto.tcp->remote_port,
        system_get_time()/1000
    );
}

/******************************************************************************
 * FunctionName : espconn_browse
 * Description  : run all open connections of the server
 * Parameters   : arg -- pointer to the espconn used for espconn_connect
 * Returns      : none
*******************************************************************************/
void espconn_browse(void *arg) {
#if DEBUG_LEVEL <= TRACE
    espconn_msg *plist = plink_active;
    struct espconn *pespconn = arg;
    crypto_parm *pcryp;
    int linefeed=0;
    
    while(plist != NULL){  //if(plist->preverse == pespconn) to select a particular socket
        if (pcryp=plist->pespconn->reserve) {
            os_printf("%08x conn, rev:%08x, nxt:%08x, act:%d, %d.%d.%d.%d:%d, cid:%02x\n",
                plist->pespconn,
                plist->preverse,
                plist->pnext,
                plist->pespconn->state,
                plist->rip[0],
                plist->rip[1],
                plist->rip[2],
                plist->rip[3],
                plist->rport,
                pcryp->connectionid
            );
        }
        plist = plist ->pnext;
    }
    for (int iid=1; iid < MAXITM + 1; iid++) {
        if(acc_items[iid].events) {
            os_printf("ev1.%d:%02x | ", iid, acc_items[iid].events);
            linefeed=1;
        }
    } 
    if (linefeed) {
        os_printf("\n");
    }

    os_timer_disarm(&browse_timer);
    os_timer_setfn(&browse_timer, (os_timer_func_t *)espconn_browse, arg);
    os_timer_arm(&browse_timer, 12000, 0);
#endif
}

/******************************************************************************
 * FunctionName : server_cleanup
 * Description  : release memory of a finished connection
 * Parameters   : arg -- Additional argument to pass to the callback function
 * Returns      : none
*******************************************************************************/
LOCAL ICACHE_FLASH_ATTR
void server_cleanup(void *arg) {
    crypto_parm *pcryp = arg;
    int iid;
    
    LOG(TRACE, "Cleaning %x @ %d CID: %d",
        pcryp,
        system_get_time() / 1000,
        pcryp->connectionid
    );
    pcryp->stale = 1;

    //clear all possible events of this connection
    for (int iid = 1; iid < MAXITM + 1; iid++) {
        acc_items[iid].events &= ~pcryp->connectionid;
    }

    while (xSemaphoreTake( pcryp->semaphore, ( portTickType ) 50 ) == pdFALSE) {
        LOG(TRACE, "Waiting %x @ %d", pcryp, system_get_time() / 1000);
    }

    LOG(TRACE, "Freeing %x @ %d", pcryp, system_get_time() / 1000);
    vSemaphoreDelete(pcryp->semaphore);
    free(pcryp);
    vTaskDelete(NULL);
}

/******************************************************************************
 * FunctionName : server_recon
 * Description  : the connection has been err, reconnection
 * Parameters   : arg -- Additional argument to pass to the callback function
 * Returns      : none
*******************************************************************************/
LOCAL ICACHE_FLASH_ATTR
void server_recon(void *arg, sint8 err) {
    struct espconn *pesp_conn = arg;

    LOG(DEBUG, "client %d.%d.%d.%d:%d disconnected with status %d",
        pesp_conn->proto.tcp->remote_ip[0],
        pesp_conn->proto.tcp->remote_ip[1],
        pesp_conn->proto.tcp->remote_ip[2],
        pesp_conn->proto.tcp->remote_ip[3],
        pesp_conn->proto.tcp->remote_port,
        err
    );
    if (pesp_conn->reserve != NULL){
        // TODO: log heap watermark for tuning the 512
        xTaskCreate(server_cleanup, "clean", 512, pesp_conn->reserve, 1, NULL);
        pesp_conn->reserve = NULL;
    }
}

/******************************************************************************
 * FunctionName : server_discon
 * Description  : the connection has been disconnected
 * Parameters   : arg -- Additional argument to pass to the callback function
 * Returns      : none
*******************************************************************************/
LOCAL ICACHE_FLASH_ATTR
void server_discon(void *arg) {
    server_recon(arg, 0);
}

/******************************************************************************
 * FunctionName : user_accept_listen
 * Description  : server listened a connection successfully
 * Parameters   : arg -- Additional argument to pass to the callback function
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
server_listen(void *arg) {
    espconn_msg *plist = plink_active;
    struct espconn *pesp_conn = arg;
    crypto_parm *pcryp;
    crypto_parm *other;
    uint32_t keepalive;
    uint32_t active = 0;
    uint32_t myconnid = 1;
    
    pcryp = (crypto_parm *)zalloc(sizeof(crypto_parm));
    
    vSemaphoreCreateBinary(pcryp->semaphore); // FIXME: is this a mutex?
    if (xSemaphoreTake( pcryp->semaphore, ( portTickType ) 0 ) == pdTRUE ) {
        LOG(TRACE, "p_sema taken");
    }
    pesp_conn->reserve = pcryp;
    pcryp->pespconn = pesp_conn;

    pcryp->stale = 0;
    pcryp->encrypted = 0;
    pcryp->countwr = 0;
    pcryp->countrd = 0;
        
    // See if we can obtain the semaphore. If the semaphore is not available wait 10 ticks to see if it becomes free.
    if( xSemaphoreTake( cid_semaphore, ( portTickType ) 10 ) == pdTRUE) {
        //run through connection list and collect current connection numbers
        while (plist != NULL){
            other = plist->pespconn->reserve;
            if (other) {
                active += other->connectionid;
            }
            plist = plist->pnext;
        }

        //find a free number in the collection
        while (active & 1) {
            myconnid <<= 1;
            active >>= 1;
        }
        pcryp->connectionid = myconnid;
        xSemaphoreGive(cid_semaphore);// We have finished accessing the shared resource. Release the semaphore.
    } else {
        // We could not obtain the semaphore and can therefore not access the shared resource safely.
        // connectionid stays zero, which needs to result in no error but also no events
        LOG(ERROR, "no Semaphore");
    }
    xSemaphoreGive( pcryp->semaphore ); //we are done manipulating pcryp things
    
    LOG(DEBUG,"%x connects from %d.%d.%d.%d:%d id:%08x",
        arg,
        pesp_conn->proto.tcp->remote_ip[0],
        pesp_conn->proto.tcp->remote_ip[1],
        pesp_conn->proto.tcp->remote_ip[2],
        pesp_conn->proto.tcp->remote_ip[3],
        pesp_conn->proto.tcp->remote_port,
        myconnid
    );

    espconn_regist_recvcb(pesp_conn, server_recv);
    espconn_regist_sentcb(pesp_conn, server_sent);
    espconn_regist_reconcb(pesp_conn, server_recon);
    espconn_regist_disconcb(pesp_conn, server_discon);
    
    espconn_set_opt(pesp_conn, ESPCONN_KEEPALIVE);
    
    keepalive = 90;
    espconn_set_keepalive(pesp_conn, ESPCONN_KEEPIDLE, &keepalive);
    
    keepalive = 10;
    espconn_set_keepalive(pesp_conn, ESPCONN_KEEPINTVL, &keepalive);
    
    keepalive = 6;
    espconn_set_keepalive(pesp_conn, ESPCONN_KEEPCNT, &keepalive);
}

void crypto_tasks() {
    crypto_parm *pcryp = NULL;
    while (1) {
        //get queue item
        LOG(TRACE, "waiting for crypto queue");
        xQueueReceive(crypto_queue, &pcryp, portMAX_DELAY);

        //execute the right routine if not stale
        if (!pcryp->stale) {
            switch (pcryp->state) { // FIXME: make an enum
                case 2:
                    crypto_setup3(pcryp);
                    break;

                case 3:
                    crypto_setup5(pcryp);
                    break;

                case 4:
                    crypto_verify1(pcryp);
                    //delay X0ms so follow up packet can jump the head of the queue
                    vTaskDelay(4); // FIXME: yield?
                    break;

                case 5:
                    crypto_verify3(pcryp);
                    //delay Y0ms so follow up packet can jump the head of the queue
                    vTaskDelay(5); // FIXME: yield?
                    break;

                case 6:
                    acc_send(pcryp);
                    break;

                case 7:
                    pairadd(pcryp);
                    break;

                case 8:
                    pairdel(pcryp);
                    break;
            }
        }

        //release semaphore
        xSemaphoreGive(pcryp->semaphore); // FIXME: is this a mutex?
    }
}

/******************************************************************************
 * FunctionName : server_init
 * Description  : parameter initialize as a server
 * Parameters   : port -- server port
 * Returns      : none
*******************************************************************************/
void ICACHE_FLASH_ATTR
server_init(uint32_t port) {
    LOCAL esp_tcp esptcp;

    // Create the semaphore to guard the connection number.
    if(cid_semaphore == NULL) {
        // FIXME: is this a mutex?
        vSemaphoreCreateBinary(cid_semaphore);
    }

    // Create the queue to handle cryptoTasks in sequence
    crypto_queue = xQueueCreate(12, sizeof(crypto_parm *));
    xTaskCreate(crypto_tasks, "crypto_tasks", 2560, NULL, 1, NULL);

    hkcesp_conn.type = ESPCONN_TCP;
    hkcesp_conn.state = ESPCONN_NONE;
    hkcesp_conn.proto.tcp = &esptcp;
    hkcesp_conn.proto.tcp->local_port = port;
    espconn_regist_connectcb(&hkcesp_conn, server_listen);

    espconn_accept(&hkcesp_conn);
    #ifndef DEMO
    espconn_regist_time(&hkcesp_conn,7200,0); //better also use keepalive ?? 180->700seconds! 100->400s 7200->8h
    #endif
    espconn_browse(&hkcesp_conn);

    LOG(TRACE, "ServerInitPriority: %d", uxTaskPriorityGet(NULL));
}