#include "lwip/ip_addr.h"

void scion_addr_val(ip_addr_t *addr, u16_t isd, u32_t ad, u8_t type, u8_t *host_addr){
    //TODO: add some sanity checks
    addr->type = type;
    *((u32_t *)addr->addr) = htonl(ISD_AS(isd, ad));
    switch(type){
        case ADDR_IPV4_TYPE:
            memcpy(addr->addr + 4, host_addr, ADDR_IPV4_LEN);
            break;
        case ADDR_IPV6_TYPE:
            memcpy(addr->addr + 4, host_addr, ADDR_IPV6_LEN);
            break;
        case ADDR_SVC_TYPE:
            memcpy(addr->addr + 4, host_addr, ADDR_SVC_LEN);
            break;
        case ADDR_NONE_TYPE:
            break;
        default:
            fprintf(stderr, "Wrong type in scion_addr()");
    }
}

void scion_addr_raw(ip_addr_t *addr, u8_t type, const u8_t *raw_addr){
    //TODO: add some sanity checks
    addr->type = type;
    if (addr->type == ADDR_IPV4_TYPE)
        memcpy(addr->addr, raw_addr, 4 + ADDR_IPV4_LEN);
    else if (addr->type == ADDR_IPV6_TYPE)
        memcpy(addr->addr, raw_addr, 4 + ADDR_IPV6_LEN);
    else if (addr->type == ADDR_SVC_TYPE)
        memcpy(addr->addr, raw_addr, 4 + ADDR_SVC_LEN);
    else if (addr->type != ADDR_NONE_TYPE){
        fprintf(stderr, "Wrong type in print_scion_addr()\n");
        return;
    }
}

void scion_addr_set(ip_addr_t *dst, const ip_addr_t *src){
    if (src == NULL)
        bzero(dst->addr, MAX_ADDR_LEN);
    else{
        dst->type = src->type;
        memcpy(dst->addr, src->addr, MAX_ADDR_LEN);
    }
}

void ip_addr_set_any(ip_addr_t *addr){
    bzero(addr->addr, MAX_ADDR_LEN);
}

u32_t ip4_addr_get_u32(const ip_addr_t *addr){
    return *((u32_t *)(addr->addr + 4));
}

int ip_addr_cmp(const ip_addr_t *addr1, const ip_addr_t *addr2){
    if (addr1 == NULL || addr2 == NULL)
        return (addr1 == addr2);
    if (bcmp(addr1->addr, addr2->addr, MAX_ADDR_LEN))
        return 0;
    return (addr1->type == addr2->type);
}

int scion_addr_isany(const ip_addr_t *addr){
    u8_t zeros[MAX_ADDR_LEN] = {0};
    if (addr == NULL)
        return 1;
    return !bcmp(addr->addr, zeros, MAX_ADDR_LEN);
}


void print_hex(char *buf, int len);
void print_scion_addr(ip_addr_t *addr){
    int len = 0;
    if (addr->type == ADDR_IPV4_TYPE)
        len = ADDR_IPV4_LEN;
    else if (addr->type == ADDR_IPV6_TYPE)
        len = ADDR_IPV6_LEN;
    else if (addr->type == ADDR_SVC_TYPE)
        len = ADDR_SVC_LEN;
    else if (addr->type != ADDR_NONE_TYPE){
        fprintf(stderr, "Wrong type in print_scion_addr()\n");
        return;
    }
    u32_t isd_as = ntohl(*((u32_t *)(addr->addr))); 
    fprintf(stderr, "(%d,%d), type:%d ", ISD(isd_as), AS(isd_as), addr->type);
    print_hex(addr->addr + 4, len);
}
