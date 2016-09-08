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
#include "libscion/scion.h"

/* Source SCION address of current_header */
ip_addr_t current_iphdr_src;
/* Destination SCION address of current_header */
ip_addr_t current_iphdr_dest;
/*  SCION path of current_header */
spath_t current_path = {.raw_path = NULL, .len = 0};
/*  SCION extensions of current_header */
exts_t current_exts;

struct netif *
scion_route(ip_addr_t *dest){
    return (struct netif *) NULL;
}

err_t
scion_input(struct pbuf *p, struct netif *inp){
    /* Packet from TCP queue: [from (HostAddr) || raw_spkt] */
    u8_t *spkt_start = p->payload + sizeof(HostAddr);
    spkt_t *spkt = parse_spkt(spkt_start);
    /* Addresses: */
    /* FIXME(PSz): memset() is required by checksum computed over SVC addr. */
    memset(current_iphdr_src.addr, 0, MAX_ADDR_LEN);
    memset(current_iphdr_dest.addr, 0, MAX_ADDR_LEN);
    scion_addr_set(&current_iphdr_src, spkt->src);
    scion_addr_set(&current_iphdr_dest, spkt->dst);
    /* Path: */
    memcpy(&current_path.first_hop, p->payload, sizeof(HostAddr));
    /* FIXME(PSz): don't have to alloc/free if already allocated space is ok. */
    /* Use realloc() or just have a static buffer. */
    if (spkt->path){
        current_path.raw_path = malloc(spkt->path->len);
        current_path.len = spkt->path->len;
        reverse_path(spkt_start, current_path.raw_path);
    }
    else{
        current_path.len = 0;
    }
    /* TODO(PSz): extensions */

    /* Point to the TCP header */
    if (pbuf_header(p, (u8_t *)p->payload - spkt->l4->payload)){
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("packet too short for tcp_input()\n"));
        pbuf_free(p);
    }
    else  /* pass to the TCP stack */
        tcp_input(p, inp);

    destroy_spkt(spkt, 1);
    if (current_path.raw_path) {
        free(current_path.raw_path);
        current_path.raw_path = NULL;
        current_path.len = 0;
    }
    return ERR_OK;
}

err_t
scion_output(struct pbuf *p, ip_addr_t *src, ip_addr_t *dst, spath_t *path,
             exts_t *exts, u8_t proto){
    /* pbufs passed to SCION must have a ref-count of 1 as their payload pointer
       gets altered as the packet is passed down the stack */
    LWIP_ASSERT("p->ref == 1", p->ref == 1);

    l4_pld tcp_data;
    tcp_data.type = IP_PROTO_TCP;
    tcp_data.len = p->len;
    tcp_data.payload = p->payload;

    /* If the first packet is to BS, then one-path extension needs to be prepended. */
    exts_t special_exts = {.count = 0, .extensions = NULL};
    if (dst->type == ADDR_SVC_TYPE){
        if (*(u16_t*)(dst->addr + ISD_AS_LEN) == SVC_BEACON &&
           TCPH_FLAGS((struct tcp_hdr *)p->payload) == TCP_SYN){
            /* Create one-hop-path extensions. */
            seh_t one_hop;
            build_one_hop_path_ext(&one_hop);
            /* Prepend one-hop-path extension. */
            int count = 1;
            if (exts)
                count += exts->count;
            special_exts.count = count;
            special_exts.extensions = (seh_t *)malloc(count);
            special_exts.extensions[0] = one_hop;
            int i;
            for (i=1; i < count; i++)
                special_exts.extensions[i] = exts->extensions[i-1];
        }
    }

    spkt_t *spkt;
    if (special_exts.count)
        spkt = build_spkt(src, dst, path, &special_exts, &tcp_data);
    else
        spkt = build_spkt(src, dst, path, exts, &tcp_data);
    u16_t spkt_len = ntohs(spkt->sch->total_len);
    u8_t packed[spkt_len];

    if (pack_spkt(spkt, packed, spkt_len))
        return ERR_VAL;
    /* Set OF indexes. */
    init_of_idx(packed);

    /* Send it through SCION overlay. */
    tcp_scion_output(packed, spkt_len, &path->first_hop);

    /* Free sch and spkt allocated with build_spkt(). */
    free(spkt->sch);
    free(spkt);
    if (special_exts.count){
        free(special_exts.extensions[0].payload);
        free(special_exts.extensions);
    }
    return ERR_OK;
}

