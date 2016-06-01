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
#define NO_SVC 0xff

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
int scion_addr_cmp_svc(const ip_addr_t *addr1, const ip_addr_t *addr2, u16_t svc);

#define ip_addr_isany(a) scion_addr_isany(a)
int scion_addr_isany(const ip_addr_t *addr);

#define ip_addr_isbroadcast(ipaddr, netif) 0
#define ip_addr_ismulticast(addr1) 0

void print_scion_addr(ip_addr_t *addr);

#ifdef __cplusplus
}
#endif

#endif /* __LWIP_IP_ADDR_H__ */
