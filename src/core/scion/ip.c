/**
 * @file
 * This is the IPv4 layer implementation for incoming and outgoing IP traffic.
 * 
 * @see ip_frag.c
 *
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
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

/////////////////////////////////////////////////////

struct path {
    u8_t *path;
    u16_t len; // in bytes
};

err_t get_path(u16_t isd, u32_t as, struct path *p){
    // validate isd,as and get path
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
    fprintf(stderr, "\n");

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
    struct pbuf *p = pbuf_alloc(PBUF_IP, len, PBUF_RAM);
    MEMCPY(p->payload, buf, len);

    tcpip_input(p, (struct netif *)NULL);
    /* pbuf_free(p); */ //FIXME(PSz): doublecheck if TCP processing releases it
}
/////////////////////////////////////////////////////////////////////////

struct netif *
ip_route(ip_addr_t *dest)
{
    // Should not be here.
    fprintf(stderr, "ip_route() NOT IMPLEMENTED!");
    return (struct netif *) NULL;
}

err_t
ip_input(struct pbuf *p, struct netif *inp){
    fprintf(stderr, "scion_input() called\n");
    // here needs to have SCION header etc..., probably extensions should be
    // handled here etc...
    current_iphdr_src.addr = 16777343; // 127.0.0.1
    current_iphdr_dest.addr = 16777343; // 127.0.0.1
    fprintf(stderr, "tcp_input() called\n");
    tcp_input(p, inp);
    return ERR_OK;
}

err_t
ip_output(struct pbuf *p, ip_addr_t *src, ip_addr_t *dst, u8_t ttl,
        u8_t tos, u8_t proto){

    add_scion_header(p, src, dst);
    fprintf(stderr, "scion_output() %lu->%lu (%dB):\n", *(u32_t *)src, *(u32_t *)dst, p->len);
    /* print_hex((char *)p->payload, p->len); */
    fprintf(stderr, "\n");
    scion_l3_input(p->payload, p->len);
}

