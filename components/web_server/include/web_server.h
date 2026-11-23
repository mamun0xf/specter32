#ifndef WEB_SERVER_H
#define WEB_SERVER_H

#include "esp_err.h"

void web_server_start(void);
void web_server_stop(void);
void web_server_broadcast_msg(const char *msg);

#endif
