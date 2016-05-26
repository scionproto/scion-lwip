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
#ifndef __LWIP_IP_ADDR_H__
#define __LWIP_IP_ADDR_H__

#include <stdint.h>
#include <string.h>
#include "lwip/opt.h"
#include "lwip/def.h"
#include "libscion/address.h"


#ifdef __cplusplus
extern "C" {
#endif

#define MAX_ADDR_LEN (4 + MAX_HOST_ADDR_LEN)

struct scion_addr {
  u8_t addr[MAX_ADDR_LEN];
  u8_t type;
};

int get_addr_len(int);
typedef struct scion_addr ip_addr_t;

void scion_addr_val(ip_addr_t *addr, u16_t isd, u32_t ad, u8_t type, u8_t *host_addr);
void scion_addr_raw(ip_addr_t *addr, u8_t type, const u8_t *raw_addr);

#define ip_addr_set(a, b) scion_addr_set(a, b)
#define ip_addr_copy(a, b) scion_addr_set(&a, &b)
void scion_addr_set(ip_addr_t *dst, const ip_addr_t *src);

#define ip_addr_set_any(a) scion_addr_set_any(a)
void scion_addr_set_any(ip_addr_t *addr);

u32_t ip4_addr_get_u32(const ip_addr_t *addr);

#define ip_addr_cmp(a, b) scion_addr_cmp(a, b)
int scion_addr_cmp(const ip_addr_t *addr1, const ip_addr_t *addr2);
int scion_addr_cmp_svc(const ip_addr_t *addr1, const ip_addr_t *addr2, u8_t svc);

#define ip_addr_isany(a) scion_addr_isany(a)
int scion_addr_isany(const ip_addr_t *addr);

#define ip_addr_isbroadcast(ipaddr, netif) 0
#define ip_addr_ismulticast(addr1) 0

void print_scion_addr(ip_addr_t *addr);

#ifdef __cplusplus
}
#endif

#endif /* __LWIP_IP_ADDR_H__ */
