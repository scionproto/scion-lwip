#include "lwip/ip_addr.h"
#define ANY_ADDR_TYPE 0xff // PSz: could we reuse NONE for that?

int get_haddr_len(int type){
    if (type == ADDR_IPV4_TYPE)
        return ADDR_IPV4_LEN;
    else if (type == ADDR_IPV6_TYPE)
        return ADDR_IPV6_LEN;
    else if (type == ADDR_SVC_TYPE)
        return ADDR_SVC_LEN;
    else if (type == ADDR_NONE_TYPE)
        return ADDR_NONE_LEN;
    fprintf(stderr, "Wrong type in get_addr_len()\n");
    return -1;
}

void scion_addr_val(ip_addr_t *addr, u16_t isd, u32_t ad, u8_t type, u8_t *host_addr){
    //TODO: add some sanity checks
    addr->type = type;
    *((u32_t *)addr->addr) = htonl(ISD_AS(isd, ad));
    int len = get_haddr_len(type);
    memcpy(addr->addr + 4, host_addr, len);
}

void scion_addr_raw(ip_addr_t *addr, u8_t type, const u8_t *raw_addr){
    //TODO: add some sanity checks
    addr->type = type;
    int len = get_haddr_len(type);
    memcpy(addr->addr, raw_addr, 4 + len);
}

void scion_addr_set(ip_addr_t *dst, const ip_addr_t *src){
    if (src == NULL)
        dst->type = ANY_ADDR_TYPE;
    else{
        dst->type = src->type;
        memcpy(dst->addr, src->addr, MAX_ADDR_LEN);
    }
}

void scion_addr_set_any(ip_addr_t *addr){
    addr->type = ANY_ADDR_TYPE;
}

u32_t ip4_addr_get_u32(const ip_addr_t *addr){
    return *((u32_t *)(addr->addr + 4));
}

int scion_addr_cmp(const ip_addr_t *addr1, const ip_addr_t *addr2){
    if (addr1 == NULL || addr2 == NULL)
        return (addr1 == addr2);
    if (addr1->type == addr2->type){
        int len = get_haddr_len(addr1->type);
        return !bcmp(addr1->addr, addr2->addr, 4 + len); 
    }
    return 0;
}

int scion_addr_cmp_svc(const ip_addr_t *addr1, const ip_addr_t *addr2, u8_t svc){
    if (addr1 == NULL || addr2 == NULL)
        return (addr1 == addr2);
    if (addr1->type == ADDR_SVC_TYPE && svc != NO_SVC)
        if (!bcmp(addr1->addr, addr2->addr, 4)) // ISD, AD are ok
            return (*((u16_t*)(addr1->addr + 4)) == svc);// TODO: SVC should be 1B long.
    return 0;
}

int scion_addr_isany(const ip_addr_t *addr){
    return addr->type == ANY_ADDR_TYPE;
}

void print_hex(char *buf, int len);
void print_scion_addr(ip_addr_t *addr){
    int len = get_haddr_len(addr->type);
    u32_t isd_as = ntohl(*((u32_t *)(addr->addr))); 
    fprintf(stderr, "(%d,%d), type:%d ", ISD(isd_as), AS(isd_as), addr->type);
    print_hex(addr->addr + 4, len);
}
