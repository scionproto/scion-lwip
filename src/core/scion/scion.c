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
#include "libscion/packet.h"

/** Source SCION address of current_header */
ip_addr_t current_iphdr_src;
/** Destination SCION address of current_header */
ip_addr_t current_iphdr_dest;
/**  SCION path of current_header */
spath_t current_path = {.raw_path = NULL};
/**  SCION extensions of current_header */
exts_t current_exts;
// FIXME(PSz): debug only
int conn_counter = 0;

void print_hex(char *buf, int len){
    int i;
    for (i=0; i<len; i++)
        fprintf(stderr, "\\x%02x", buf[i]);
}

void
scion_l3_input(u8_t *buf, int len){
    struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
    MEMCPY(p->payload, buf, len);
    printf("SCION_L3_INPUT(%dB):", len);
    tcpip_input(p, (struct netif *)NULL);
}

struct netif *
scion_route(ip_addr_t *dest)
{
    // Should not be here.
    fprintf(stderr, "ip_route() NOT IMPLEMENTED!");
    return (struct netif *) NULL;
}

err_t
scion_input(struct pbuf *p, struct netif *inp){
    fprintf(stderr, "scion_input() called (%dB)\n", p->len);
    spkt_t *spkt = parse_spkt(p->payload);
    // Addresses:
    // FIXME(PSz): bzero() is required by checksum computed over SVC addr.
    bzero(current_iphdr_src.addr, MAX_ADDR_LEN);
    bzero(current_iphdr_dest.addr, MAX_ADDR_LEN);
    scion_addr_set(&current_iphdr_src, spkt->src);
    scion_addr_set(&current_iphdr_dest, spkt->dst);
    // Path:
    // FIXME(PSz): don't have to alloc, just point
    if (current_path.raw_path != NULL) //FIXME(PSz): don't need to free if lengts are OK
        free(current_path.raw_path);
    char tmp[200];
    sprintf(tmp, "%s%d", "REVERSEDREVERSED", conn_counter);
    current_path.len = strlen(tmp);
    current_path.raw_path = malloc(current_path.len);
    memcpy(current_path.raw_path, tmp, current_path.len);
    conn_counter++;
    // TODO(PSz): extensions
    destroy_spkt(spkt, 1);

    tcp_input(p, inp);
    return ERR_OK;
}

err_t
scion_output(struct pbuf *p, ip_addr_t *src, ip_addr_t *dst, spath_t *path,
             exts_t *exts, u8_t proto){
    fprintf(stderr, "scion_output() called(%d)\n", p->len);
    /* pbufs passed to SCION must have a ref-count of 1 as their payload pointer
       gets altered as the packet is passed down the stack */
    LWIP_ASSERT("p->ref == 1", p->ref == 1);

    l4_pld tcp_data;
    tcp_data.type = IP_PROTO_TCP;
    tcp_data.len = p->len;
    tcp_data.payload = p->payload;

    spkt_t *spkt = build_spkt(src, dst, path, exts, &tcp_data);
    u16_t total_len = ntohs(spkt->sch->total_len);
    u8_t packed[total_len];
    if (pack_spkt(spkt, packed, total_len)){
        fprintf(stderr, "pack_sptk() failed\n");
        return ERR_VAL;
    }
    // Free sch and spkt allocated with build_spkt().
    free(spkt->sch);
    free(spkt);

    scion_l3_input(packed, total_len);
    return ERR_OK;
}

