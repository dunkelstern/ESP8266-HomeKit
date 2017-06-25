#ifndef server__url_h__included
#define server__url_h__included

#define URLSize 16

typedef enum ProtocolType {
    GET = 0,
    POST,
    PUT,
} ProtocolType;

typedef struct URL_Frame {
    enum ProtocolType Type;
    char pSelect[URLSize];
    char pCommand[URLSize];
    char pFilename[URLSize];
} URL_Frame;

void ICACHE_FLASH_ATTR
parse_url(char *precv, URL_Frame *purl_frame);

#endif
