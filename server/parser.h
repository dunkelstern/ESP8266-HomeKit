#ifndef server__parser_h__included
#define server__parser_h__included

char *parse_cgi(char *in);
void parse_chas(void *arg, char *in);

bool ICACHE_FLASH_ATTR
check_data(char *precv, uint16_t length);

#endif