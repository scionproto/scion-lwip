#ifndef __LWIP_SCION_H__
#define __LWIP_SCION_H__
#include "lwip/pbuf.h"
#include "lwip/ip_addr.h"

// void scion_input(struct pbuf *p, struct netif *inp);
void scion_output(struct pbuf *p, ip_addr_t *src, ip_addr_t *dst,
       u8_t ttl, u8_t tos, u8_t proto);
void scion_input(struct pbuf *p, struct netif *inp);
#endif
