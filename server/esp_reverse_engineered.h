#ifndef server__esp_reverse_engineered_h__included
#define server__esp_reverse_engineered_h__included

typedef struct _espconn_msg{
    struct espconn *pespconn;
    void *pcommon; //at least that is what I suspect
    int rport;
    uint8 rip[4];
    void *p05;
    void *p06;
    void *p07;
    void *p08;
    void *p09;
    void *p10;
    void *p11;
    void *p12;
    int i13;
    void *p14;
    void *p15;
    void *p16;
    void *p17;
    void *p18;
    int i19;
    void *p20;
    void *p21;
    void *p22;
    void *preverse;
    void *pssl;
    struct _espconn_msg *pnext;
    void *p26;
    void *p27;
    int i28;
}espconn_msg;

#endif