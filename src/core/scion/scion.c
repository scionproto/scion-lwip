/*
 * Copyright 2016 ETH Zurich
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *  limitations under the License.
 */
#include "lwip/opt.h"
#include "lwip/ip.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/ip_frag.h"
#include "lwip/inet_chksum.h"
#include "lwip/netif.h"
#include "lwip/icmp.h"
#include "lwip/igmp.h"
#include "lwip/raw.h"
#include "lwip/udp.h"
#include "lwip/tcp_impl.h"
#include "lwip/autoip.h"
#include "lwip/stats.h"
#include "arch/perf.h"
#include "lwip/tcpip.h"

/** Source IP address of current_header */
ip_addr_t current_iphdr_src;
/** Destination IP address of current_header */
ip_addr_t current_iphdr_dest;
/**  SCION path of current_header */
spath_t current_path = {.path = NULL};
/**  SCION extensions of current_header */
exts_t current_exts;
int conn_counter = 0;


err_t get_path(u16_t isd, u32_t as, spath_t *p){
    // validate isd,as and get path
    // caller has to remember to free(p->path);
    int plen = 24;
    p->path = malloc(plen);
    memcpy(p->path, "012345678901234567890123", plen);
    p->len = plen;
    return ERR_OK;
}

void print_hex(char *buf, int len){
    int i;
    for (i=0; i<len; i++)
        fprintf(stderr, "\\x%02x", buf[i]);
}

err_t 
add_scion_header(struct pbuf *p, ip_addr_t *src, ip_addr_t *dest)
{
  /* pbufs passed to IP must have a ref-count of 1 as their payload pointer
     gets altered as the packet is passed down the stack */
    LWIP_ASSERT("p->ref == 1", p->ref == 1);

    //here call get_path etc...


  /* Should the IP header be generated or is it already included in p? */
    /* u16_t ip_hlen = IP_HLEN; */
    /* generate IP header */
    /* if (pbuf_header(p, IP_HLEN)) { */
    /*   LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip_output: not enough room for IP header in pbuf\n")); */
    /*   return ERR_BUF; */
    /* } */

    /* iphdr = (struct ip_hdr *)p->payload; */
    /* LWIP_ASSERT("check that first pbuf can hold struct ip_hdr", */
    /*            (p->len >= sizeof(struct ip_hdr))); */
}

void 
scion_l3_input(u8_t *buf, int len){
    struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
    MEMCPY(p->payload, buf, len);
    printf("SCION_L3_INPUT(%dB):", len); 
    tcpip_input(p, (struct netif *)NULL);
    /* pbuf_free(p); */ //FIXME(PSz): doublecheck if TCP processing releases it
}
/////////////////////////////////////////////////////////////////////////

struct netif *
scion_route(ip_addr_t *dest)
{
    // Should not be here.
    fprintf(stderr, "ip_route() NOT IMPLEMENTED!");
    return (struct netif *) NULL;
}

err_t
scion_input(struct pbuf *p, struct netif *inp){
    fprintf(stderr, "scion_input() called\n");
    // here needs to have SCION header etc..., probably extensions should be
    // handled here etc...
    /* u8_t def_addr[] = {127, 0, 0, 1}; */
    /* scion_addr_val(&current_iphdr_src, 1, 2, ADDR_IPV4_TYPE, def_addr); */
    /* scion_addr_val(&current_iphdr_dest, 1, 2, ADDR_IPV4_TYPE, def_addr); */

    // FIXME(PSz): don't have to alloc, just point
    if (current_path.path != NULL) //FIXME(PSz): don't need to free if lengts are OK
        free(current_path.path);
    char tmp[200];
    sprintf(tmp, "%s%d", "REVERSED", conn_counter);
    current_path.len = strlen(tmp);
    current_path.path = malloc(current_path.len);
    memcpy(current_path.path, tmp, current_path.len);
    conn_counter++;

/// Addresses
//  FIXME(PSz): bzero() is required by checksum computed over SVC addr.
    bzero(current_iphdr_src.addr, MAX_ADDR_LEN);
    bzero(current_iphdr_dest.addr, MAX_ADDR_LEN);
    u8_t *ptmp = p->payload;
    scion_addr_raw(&current_iphdr_src, ptmp[0], ptmp + 1);
    ptmp += 1 + MAX_ADDR_LEN;
    scion_addr_raw(&current_iphdr_dest, ptmp[0], ptmp + 1);
//
    tcp_input(p, inp);
    return ERR_OK;
}

err_t
scion_output(struct pbuf *p, ip_addr_t *src, ip_addr_t *dst, spath_t *path,
             exts_t *exts, u8_t proto){
    add_scion_header(p, src, dst);

    fprintf(stderr, "scion_output() called\n");
      print_scion_addr(src);
      print_scion_addr(dst);
    if (path != NULL)
        fprintf(stderr, "PATH(%dB): %.*s\n", path->len, path->len, (char*)path->path);
    else
        fprintf(stderr, "PATH is NULL\n");
    fprintf(stderr, "\n");

// Add addresses to the packet
    u8_t buf[2 + 2*MAX_ADDR_LEN + p->len], *ptmp;
    ptmp = buf;
    ptmp[0] = src->type;
    ptmp++;
    memcpy(ptmp, src->addr, MAX_ADDR_LEN);
    ptmp+=MAX_ADDR_LEN;
    ptmp[0] = dst->type;
    ptmp++;
    memcpy(ptmp, dst->addr, MAX_ADDR_LEN);
    ptmp+=MAX_ADDR_LEN;
    memcpy(ptmp, p->payload, p->len);
    scion_l3_input(buf, 2 + 2*MAX_ADDR_LEN + p->len);
}

