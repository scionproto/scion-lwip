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

#define MAX_ADDR_LEN (ISD_AS_LEN + MAX_HOST_ADDR_LEN)
#define NO_SVC 0xffff
#define ANY_ADDR_TYPE 0xff /* PSz: could we reuse NONE for that? */

typedef saddr_t ip_addr_t;

void scion_addr_from_raw(saddr_t *, u8_t, const char *);
#define ip_addr_set(a, b) scion_addr_set(a, b)
#define ip_addr_copy(a, b) scion_addr_set(&a, &b)
void scion_addr_set(saddr_t *dst, const saddr_t *src);

#define ip_addr_set_any(a) scion_addr_set_any(a)
void scion_addr_set_any(saddr_t *addr);

/* FIXME(PSz): remove after we use generic cheksum. */
u32_t ip4_addr_get_u32(const saddr_t *addr);

#define ip_addr_cmp(a, b) scion_addr_cmp(a, b)
int scion_addr_cmp(const saddr_t *addr1, const saddr_t *addr2);
int scion_addr_cmp_svc(const saddr_t *addr1, const saddr_t *addr2, u16_t svc);

#define ip_addr_isany(a) scion_addr_isany(a)
int scion_addr_isany(const saddr_t *addr);

#define ip_addr_isbroadcast(ipaddr, netif) 0
#define ip_addr_ismulticast(addr1) 0

/* Forward declaration to not include netif.h */
struct netif;

#ifdef __cplusplus
}
#endif

#endif /* __LWIP_IP_ADDR_H__ */
