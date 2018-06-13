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
#include <assert.h>
#include "lwip/ip_addr.h"

int scion_addr_from_raw(saddr_t *addr, u8_t type, const char *raw_addr, int raw_addr_len){
    if (!(type < ADDR_TYPE_N)) {
        return -1;
    }
    addr->type = type;
    int len = ISD_AS_LEN + get_addr_len(type);
    if (len != raw_addr_len) {
        // Expected len from address type does not match actual address len
        return -1;
    }
    memcpy(addr->addr, raw_addr, len);
    return 0;
}

void scion_addr_set(saddr_t *dst, const saddr_t *src){
    if (src == NULL)
        dst->type = ANY_ADDR_TYPE;
    else
        memcpy(dst, src, sizeof(saddr_t));
}

void scion_addr_set_any(saddr_t *addr){
    addr->type = ANY_ADDR_TYPE;
}

int scion_addr_cmp(const saddr_t *addr1, const saddr_t *addr2){
    if (addr1 == NULL || addr2 == NULL)
        return (addr1 == addr2);
    if (addr1->type == addr2->type){
        int len = get_addr_len(addr1->type);
        return !memcmp(addr1->addr, addr2->addr, ISD_AS_LEN + len);
    }
    return 0;
}

int scion_addr_cmp_svc(const saddr_t *addr1, const saddr_t *addr2, u16_t svc){
    if (addr1 == NULL || addr2 == NULL)
        return (addr1 == addr2);
    if (addr1->type == ADDR_SVC_TYPE && svc != NO_SVC)
        if (!memcmp(addr1->addr, addr2->addr, ISD_AS_LEN))  /* ISD, AD are ok */
            return (*((u16_t*)(addr1->addr + ISD_AS_LEN)) == svc);
    return 0;
}

int scion_addr_isany(const saddr_t *addr){
    return addr->type == ANY_ADDR_TYPE;
}
