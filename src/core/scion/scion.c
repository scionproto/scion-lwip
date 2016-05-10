#include <stdio.h>
#include <stdint.h>
#include "lwip/pbuf.h"
#include "lwip/scion.h"
#include "lwip/ip_addr.h"
#include "lwip/ip.h"
#include "lwip/tcp_impl.h"
#include "lwip/tcpip.h"
#include "lwip/netif.h"

void print_hex(char *buf, int len){
    int i;
    for (i=0; i<len; i++)
        fprintf(stderr, "\\x%02x", buf[i]);
    fprintf(stderr, "\n");

}

err_t add_ip_header(struct pbuf *p, ip_addr_t *src, ip_addr_t *dest,
       u8_t ttl, u8_t tos, u8_t proto, struct netif *netif, void *ip_options,
       u16_t optlen)
{
  struct ip_hdr *iphdr;

  /* pbufs passed to IP must have a ref-count of 1 as their payload pointer
     gets altered as the packet is passed down the stack */
  LWIP_ASSERT("p->ref == 1", p->ref == 1);


  /* Should the IP header be generated or is it already included in p? */
    u16_t ip_hlen = IP_HLEN;
    /* generate IP header */
    if (pbuf_header(p, IP_HLEN)) {
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip_output: not enough room for IP header in pbuf\n"));
      return ERR_BUF;
    }

    iphdr = (struct ip_hdr *)p->payload;
    LWIP_ASSERT("check that first pbuf can hold struct ip_hdr",
               (p->len >= sizeof(struct ip_hdr)));

    IPH_TTL_SET(iphdr, ttl);
    IPH_PROTO_SET(iphdr, proto);

    /* src and dest cannot be NULL here */
    ip_addr_copy(iphdr->src, *src);
    ip_addr_copy(iphdr->dest, *dest);

    IPH_VHL_SET(iphdr, 4, ip_hlen / 4);
    IPH_TOS_SET(iphdr, tos);
    IPH_LEN_SET(iphdr, htons(p->tot_len));
    IPH_OFFSET_SET(iphdr, 0);
    IPH_ID_SET(iphdr, htons(1));


    IPH_CHKSUM_SET(iphdr, 0);
    ip_debug_print(p);
}


/* FIXME(PSz): Taken from netif.c */
static err_t
netif_loopif_init(struct netif *netif)
{
  /* initialize the snmp variables and counters inside the struct netif
   * ifSpeed: no assumption can be made!
   */
  NETIF_INIT_SNMP(netif, snmp_ifType_softwareLoopback, 0);

  netif->name[0] = 'l';
  netif->name[1] = 'o';
  netif->output = netif_loop_output;
  return ERR_OK;
}
struct netif mk_netif(){
    struct netif netif;
    ip_addr_t ipaddr, netmask, gateway;
    IP4_ADDR(&gateway, 127,0,0,1);
    IP4_ADDR(&ipaddr, 127,0,0,1);
    IP4_ADDR(&netmask, 255,255,255,0);
    netif_add(&netif, &ipaddr, &netmask, &gateway, NULL, netif_loopif_init, tcpip_input);
    return netif;
}

void scion_l3_input(u8_t *buf, int len){
    struct pbuf *p = pbuf_alloc(PBUF_IP, len, PBUF_RAM);
    MEMCPY(p->payload, buf, len);

    struct netif netif = mk_netif();
    tcpip_input(p, &netif);
    /* pbuf_free(p); */ //FIXME(PSz): doublecheck if TCP processing releases it
}

void scion_output(struct pbuf *p, ip_addr_t *src, ip_addr_t *dst, u8_t ttl,
        u8_t tos, u8_t proto){
    LWIP_UNUSED_ARG (ttl);
    LWIP_UNUSED_ARG (tos);

    uint32_t saddr = *(uint32_t *)src;                                                              
    uint32_t daddr = *(uint32_t *)dst;

    fprintf(stderr, "PSz: scion_output() called");
    struct netif netif = mk_netif();
    add_ip_header(p, src, dst, ttl, tos, proto, &netif, NULL, 0); // For now, debug reasons.
    fprintf(stderr, "PSz: sending %lu->%lu (%dB):\n", saddr, daddr, p->len);
    print_hex((char *)p->payload, p->len);
    fprintf(stderr, "\n\n");
    scion_l3_input(p->payload, p->len);
}

void scion_input(struct pbuf *p, struct netif *inp){
    IP4_ADDR(&current_iphdr_src, 127,0,0,1);
    IP4_ADDR(&current_iphdr_dest, 127,0,0,1);
    fprintf(stderr, "scion_input() called\n");
    // here needs to have SCION header etc..., probably extensions should be
    // handled here etc...
    fprintf(stderr, "tcp_input() called\n");
    tcp_input(p, inp);
}
