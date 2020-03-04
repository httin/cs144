/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#include <arpa/inet.h>
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
#undef  DEBUG_ENABLE

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    /* Add initialization code here! */
    if(sr->nat_mode) {
      sr_nat_init(&(sr->nat));
      sr->nat.icmp_query_timeout = sr->icmp_query_timeout;
      sr->nat.tcp_established_timeout = sr->tcp_established_timeout;
      sr->nat.tcp_transitory_timeout = sr->tcp_transitory_timeout;
    }
} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
bool length_is_valid(uint8_t* buf, enum sr_ethertype ether_type, unsigned int len) {
  if(ether_type == ethertype_arp) {
    return (len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  } else if (ether_type == ethertype_ip) {
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
    return (len >= ntohs(ip_hdr->ip_len) + sizeof(sr_ethernet_hdr_t));
  }
  return false;
}

void build_ethernet_hdr(uint8_t* buf, uint8_t dhost[6], uint8_t shost[6], uint16_t type) {
  sr_ethernet_hdr_t *ethernet = (sr_ethernet_hdr_t *) buf;
  memcpy(ethernet->ether_dhost, dhost, ETHER_ADDR_LEN);
  memcpy(ethernet->ether_shost, shost, ETHER_ADDR_LEN);
  ethernet->ether_type = type;
}

void build_ip_hdr(uint8_t* buf, uint8_t ip_hl, uint8_t ip_v, uint8_t ip_tos,
                  uint16_t ip_len, uint16_t ip_id, uint16_t ip_off, uint8_t ip_ttl,
                  uint8_t ip_p, uint32_t ip_src, uint32_t ip_dst) {
  sr_ip_hdr_t *ip = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
  ip->ip_hl     = ip_hl;    /* header length (x4 bytes), minimun = 5 */
  ip->ip_v      = ip_v;     /* version: 4 - Internet Protocol */
  ip->ip_tos    = ip_tos;   /* Type of Service: 0x00 - Routine */
  ip->ip_len    = ip_len;   /* Total length: 84 */
  ip->ip_id     = ip_id;    /* ID: = ID received */
  ip->ip_off    = ip_off;   /* Fragment offset: 0x4000 - Don't fragment */
  ip->ip_ttl    = ip_ttl;   /* Time to live */
  ip->ip_p      = ip_p;     /* Protocol: 1(IP), 6(TCP), 17(UDP) */
  ip->ip_sum    = 0;        /* Checksum */
  ip->ip_src    = ip_src;   /* Source IP */
  ip->ip_dst    = ip_dst;   /* Destination IP */
  ip->ip_sum    = cksum(buf + sizeof(sr_ethernet_hdr_t), ip_hl*4);
}

int send_icmp_exception(struct sr_instance* sr, uint32_t dip, uint8_t dmac[ETHER_ADDR_LEN],
         uint16_t ip_id, uint8_t *icmp_data, uint16_t icmp_data_len, int icmp_exeption_type) {
  fprintf(stderr, "Sending ICMP(%lu) type %d to ", 34 + sizeof(sr_icmp_hdr_t) + icmp_data_len, icmp_exeption_type);
  print_addr_ip_int(ntohl(dip));
   
  struct sr_rt *rt = longest_prefix_match(sr, dip);
  struct sr_if *interface = sr_get_interface(sr, rt->interface);
  
  uint32_t icmp_len = sizeof(sr_icmp_hdr_t) + icmp_data_len; 
  sr_icmp_hdr_t *icmp = malloc(icmp_len); /* contain ip header */
 
  if (icmp_exeption_type == DEST_NET_UNREACHABLE) {
      icmp->icmp_type = 3;
      icmp->icmp_code = 0;
      fprintf(stderr, " (Destination net unreachable)... ");
  } else if (icmp_exeption_type == DEST_HOST_UNREACHABLE) {
      icmp->icmp_type = 3;
      icmp->icmp_code = 1;
      fprintf(stderr, " (Destination host unreachable)... ");
  } else if (icmp_exeption_type == PORT_UNREACHABLE) {
      icmp->icmp_type = 3;
      icmp->icmp_code = 3;
      fprintf(stderr, " (Port unreachable)... ");
  } else if (icmp_exeption_type == TTL_EXCEEDED) {
      icmp->icmp_type = 11;
      icmp->icmp_code = 0;
      fprintf(stderr, " (TTL exceeded)... ");
  }

  icmp->icmp_id = 0;
  icmp->icmp_seq = 0;
  memcpy((uint8_t *)icmp + sizeof(sr_icmp_hdr_t), icmp_data, icmp_data_len);
  icmp->icmp_sum = 0;
  icmp->icmp_sum = cksum(icmp, icmp_len);
  
  uint8_t *buf = calloc(1, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + icmp_len);
  build_ethernet_hdr(buf, dmac, interface->addr, htons(ethertype_ip));
  build_ip_hdr(buf, 5, 4, 0, htons(20 + icmp_len), htons(ip_id), htons(IP_DF), 
               64, ip_protocol_icmp, interface->ip, dip);
  memcpy(buf + 14 + 20, icmp, icmp_len);

  int res = send_pack(sr, dip, buf, 14 + 20 + icmp_len);
  free(icmp);
  free(buf);
  return res;
}

struct sr_if *find_if_from_ip(struct sr_instance* sr, uint32_t dst_ip) {
  struct sr_if *if_walker = NULL;
  assert(sr->if_list);
  if_walker = sr->if_list;
  
  while(if_walker) {
    if(if_walker->ip == dst_ip) 
      return if_walker;
    if_walker = if_walker->next;
  }
  return NULL;
}

struct sr_rt *longest_prefix_match(struct sr_instance *sr, uint32_t ip) {
  struct sr_rt *rt = NULL, *ans = NULL;
  unsigned long max_prefix = 0;
  struct in_addr addr;
  addr.s_addr = ip;
  for(rt = sr->routing_table; rt != NULL; rt = rt->next) {
    if(((rt->dest.s_addr & rt->mask.s_addr) == (addr.s_addr & rt->mask.s_addr)) 
         && (max_prefix <= rt->mask.s_addr)) {
      ans = rt;
      max_prefix = rt->mask.s_addr;
    }
  }
  return ans;
}

int send_pack(struct sr_instance *sr, uint32_t dip, uint8_t *buf, uint32_t len) {
  struct sr_rt *rt;
  rt = longest_prefix_match(sr, dip);
  if(rt == NULL)
    return DEST_NET_UNREACHABLE; 
  
  sr_send_packet(sr, buf, len, rt->interface);
  fprintf(stderr, "Packet %u bytes sent from %s to ", len, rt->interface);
  print_addr_ip_int(ntohl(dip));
  return 0; /* SUCCESSFULLY */
}

void handle_ip_packet_for_router(struct sr_instance *sr, uint8_t* packet, 
      unsigned int len, char* interface) {
  sr_ethernet_hdr_t *get_eth_hdr = (sr_ethernet_hdr_t *) packet;
  sr_ip_hdr_t *get_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if *incoming_iface = sr_get_interface(sr, interface);

  if(get_ip_hdr->ip_p == ip_protocol_icmp) {
    sr_icmp_hdr_t *get_icmp_hdr = (sr_icmp_hdr_t *)((uint8_t*)get_ip_hdr + sizeof(sr_ip_hdr_t));
    if(get_icmp_hdr->icmp_type != 0x08) /* ICMP is not an echo request -> drop packet */
      return;
    /* verify icmp checksum */
    uint16_t get_icmp_cksum = get_icmp_hdr->icmp_sum;
    get_icmp_hdr->icmp_sum = 0;
    get_icmp_hdr->icmp_sum = cksum((uint8_t*)get_icmp_hdr, ntohs(get_ip_hdr->ip_len) - get_ip_hdr->ip_hl * 4);
    if(get_icmp_cksum != get_icmp_hdr->icmp_sum) {
      fprintf(stderr, "[ERROR] Invalid ICMP checksum! Get: %u, Compute: %u\n",
                       get_icmp_cksum, get_icmp_hdr->icmp_sum);
      return;
    }
    /* make icmp echo reply */
    uint8_t *echo_reply = calloc(1, len);
    sr_icmp_hdr_t *icmp = (sr_icmp_hdr_t *)(echo_reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    build_ethernet_hdr(echo_reply, get_eth_hdr->ether_shost, 
                       incoming_iface->addr, get_eth_hdr->ether_type);
    build_ip_hdr(echo_reply, 5, 4, 0, get_ip_hdr->ip_len, 
                 get_ip_hdr->ip_id, get_ip_hdr->ip_off, 64,
                 ip_protocol_icmp, get_ip_hdr->ip_dst, get_ip_hdr->ip_src);
    /* ICMP frame */
    memcpy(echo_reply + 34 + sizeof(sr_icmp_hdr_t), packet + 34 + sizeof(sr_icmp_hdr_t), 
           len - 34 - sizeof(sr_icmp_hdr_t));
    icmp->icmp_id = get_icmp_hdr->icmp_id;
    icmp->icmp_seq = get_icmp_hdr->icmp_seq;
    icmp->icmp_sum = cksum(icmp, ntohs(get_ip_hdr->ip_len) - get_ip_hdr->ip_hl * 4);
    send_pack(sr, get_ip_hdr->ip_src, echo_reply, len);
    free(echo_reply);
  } else if (get_ip_hdr->ip_p == ip_protocol_tcp || get_ip_hdr->ip_p == ip_protocol_udp) {
    /* packet contains a TCP or UDP payload, send an ICMP port unreachable to sending host */
    send_icmp_exception(sr, get_ip_hdr->ip_src, get_eth_hdr->ether_shost, htons(get_ip_hdr->ip_id) + 1, 
        packet + sizeof(sr_ethernet_hdr_t), htons(get_ip_hdr->ip_len), PORT_UNREACHABLE);
  } else { /* ignore the packet */
    return;
  }
}

int forward_packet(struct sr_instance *sr, uint8_t* pac, uint32_t len) {
  uint8_t *buf = malloc(len);
  memcpy(buf, pac, len);

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) buf;
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
#ifdef DEBUG_ENABLE
  fprintf(stderr, "Forwarding IP(%"PRIu32") packet to ", len);
  print_addr_ip_int(ntohl(ip_hdr->ip_dst));
#endif
  if (ip_hdr->ip_ttl == 1)
      return TTL_EXCEEDED;

  struct sr_rt *rt = longest_prefix_match(sr, ip_hdr->ip_dst);
  if (rt == NULL)
      return DEST_NET_UNREACHABLE;

  struct sr_if* interface = sr_get_interface(sr, rt->interface);
  struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);

  if (entry) {
      memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
      memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
  } else { /* Case: arp cache miss */
#ifdef  DEBUG_ENABLE
      fprintf(stderr, "MAC not found in ARP cache, queuing packet to requests list and handle...\n");
#endif
      struct sr_arpreq *req;
      req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, buf, len, rt->interface);
      sr_handle_arpreq(sr, req); /* success */
      return 0;
  }

  ip_hdr->ip_ttl--;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
  /* forwading packet to next-hop IP address */
  int res = send_pack(sr, ip_hdr->ip_dst, buf, len);
  free(buf);
  return res;
}

void send_outstanding_packets(struct sr_instance* sr, struct sr_packet* packets, uint8_t* dst_mac) {
  while (packets != NULL) {
    sr_ethernet_hdr_t* packet = (sr_ethernet_hdr_t*)(packets->buf);
    struct sr_if* if_match = sr_get_interface(sr, packets->iface);
    memcpy(packet->ether_dhost, dst_mac, ETHER_ADDR_LEN);
    memcpy(packet->ether_shost, if_match->addr, ETHER_ADDR_LEN);
    sr_send_packet(sr, packets->buf, packets->len, packets->iface);
    packets = packets->next;
  }
}

void arpcache_send_all_packet(struct sr_instance *sr, struct sr_packet *pack) {
  if(pack == NULL)    return;

#ifdef  DEBUG_ENABLE
  struct in_addr ip;
  fprintf(stderr, "Sending packet in queue\n(");
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pack->buf + sizeof(sr_ethernet_hdr_t));
  ip.s_addr = ip_hdr->ip_src;
  fprintf(stderr, "Source: %s  ----  ", inet_ntoa(ip));
  ip.s_addr = ip_hdr->ip_dst;
  fprintf(stderr, "Target: %s  ----  ", inet_ntoa(ip));
  fprintf(stderr, "ID: %u)...\n", htons(ip_hdr->ip_id));
#endif    
  forward_packet(sr, pack->buf, pack->len);
  arpcache_send_all_packet(sr, pack->next);
}

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** %s -> Received packet of length %d\n", interface, len);
  /* fill in code here */
  uint8_t *buf = malloc(len);
  memcpy(buf, packet, len); /* make a copy of the packet -> buf */
  sr_ethernet_hdr_t *get_eth_hdr = (sr_ethernet_hdr_t *) buf; /* get ethernet header */
  if(!length_is_valid(buf, ntohs(get_eth_hdr->ether_type), len)) {
    fprintf(stderr, "Invalid packet length %u\n", len);
    return;
  }

  switch(ntohs(get_eth_hdr->ether_type)) {
    case ethertype_ip: /* IP = 0x0800 */
    { 
      sr_ip_hdr_t *get_ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
      /* verify IP checksum */
      uint16_t get_cksum = get_ip_hdr->ip_sum;
      get_ip_hdr->ip_sum = 0;
      get_ip_hdr->ip_sum = cksum(get_ip_hdr, get_ip_hdr->ip_hl*4);
      if(get_cksum != get_ip_hdr->ip_sum) {
        fprintf(stderr, "[ERROR] Invalid IP checksum! Get: %#x, Compute: %#x\n",
                get_cksum, get_ip_hdr->ip_sum);
        return;
      }
      /* if we're in NAT mode, handle IP packet */
      if(sr->nat_mode) {
        handle_nat_ip_packet(sr, buf, len, interface);
        return;
      }
      /* check destination ip if it is one of the router interfaces --> handle it */ 
      if(find_if_from_ip(sr, get_ip_hdr->ip_dst)) {
        handle_ip_packet_for_router(sr, buf, len, interface);
      } else { /* IP packet whose destination is not one of the router's interfaces -> forward */
        int res = forward_packet(sr, buf, len);
        if(res != 0)
          send_icmp_exception(sr, get_ip_hdr->ip_src, get_eth_hdr->ether_shost, htons(get_ip_hdr->ip_id) + 1, 
                buf + sizeof(sr_ethernet_hdr_t), htons(get_ip_hdr->ip_len), res);
      } 
      break;    
    }
    case ethertype_arp:/* ARP = 0x0806 */
    {
      sr_arp_hdr_t *get_arp_hdr = (sr_arp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
      struct sr_if *incoming_iface = sr_get_interface(sr, interface);

      if(ntohs(get_arp_hdr->ar_op) == arp_op_request) { 
        sr_arpcache_insert(&(sr->cache), get_arp_hdr->ar_sha, get_arp_hdr->ar_sip);
        uint8_t *arp_reply = malloc(len);
        /* build Ethernet frame */
        build_ethernet_hdr(arp_reply, get_eth_hdr->ether_shost, incoming_iface->addr, htons(ethertype_arp));
        /* build ARP Reply frame */
        sr_arp_hdr_t *arp = (sr_arp_hdr_t *)(arp_reply + sizeof(sr_ethernet_hdr_t));
        arp->ar_hrd = get_arp_hdr->ar_hrd;   /* hardware type: Ethernet */
        arp->ar_pro = get_arp_hdr->ar_pro;   /* protocol type: IP - 0x0800 */
        arp->ar_hln = ETHER_ADDR_LEN;        /* length of mac */
        arp->ar_pln = 4;                     /* length of IPv4 */
        arp->ar_op  = htons(arp_op_reply);   /* ARP opcode */
        memcpy(arp->ar_sha, incoming_iface->addr, ETHER_ADDR_LEN); /* source mac */
        arp->ar_sip = get_arp_hdr->ar_tip;                         /* source IP  */
        memcpy(arp->ar_tha, get_arp_hdr->ar_sha, ETHER_ADDR_LEN);  /* target mac */
        arp->ar_tip = get_arp_hdr->ar_sip;                         /* target IP  */
        
        if(!sr_send_packet(sr, arp_reply, len, incoming_iface->name)) {
          fprintf(stderr, "ARP Reply packet %u bytes sent from %s to ", len, incoming_iface->name);
          print_addr_ip_int(ntohl(get_arp_hdr->ar_sip));
        } 
      } else if (ntohs(get_arp_hdr->ar_op) == arp_op_reply) { 
        struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), get_arp_hdr->ar_sha, get_arp_hdr->ar_sip);
#ifdef  DEBUG_ENABLE
        fprintf(stderr, "New arp entry inserted, ARP Cache Table:\n");
        sr_arpcache_dump(&(sr->cache));
#endif        
        if(req != NULL) {    
          send_outstanding_packets(sr, req->packets, get_arp_hdr->ar_sha);
          sr_arpreq_destroy(&(sr->cache), req);
        } else {
          return; /* there is no pending request for this source ip */
        }
      } else {
        fprintf(stderr, "Unrecognize ARP opcode 0x%.4x\n", ntohs(get_arp_hdr->ar_op));
      } /* End of check ARP opcode */
      break; /* End ARP Packet */
    }
    default:
      fprintf(stderr, "Ethertype %d Invalid!", ntohs(get_eth_hdr->ether_type));
  }
}/* end sr_ForwardPacket */

/* return the mapping if an external PORT or ICMP ID has a mapping to an internal address.
   MUST FREE the returned structure if it is not NULL. */
struct sr_nat_mapping *find_external_mapping(struct sr_instance* sr, uint8_t *buf) {

  sr_ip_hdr_t *get_ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
  sr_nat_mapping_type mapping_type;
  uint16_t aux_ext;
  if(get_ip_hdr->ip_p == ip_protocol_icmp) {
    sr_icmp_hdr_t *get_icmp_hdr = (sr_icmp_hdr_t *)((uint8_t *)get_ip_hdr + sizeof(sr_ip_hdr_t));
    if(get_icmp_hdr->icmp_type != 0x08 && get_icmp_hdr->icmp_code != 0x00)
      return NULL;
    mapping_type = nat_mapping_icmp;
    aux_ext = ntohs(get_icmp_hdr->icmp_id);
  } else if (get_ip_hdr->ip_p == ip_protocol_tcp) {
    sr_tcp_hdr_t *get_tcp_hdr = (sr_tcp_hdr_t *)((uint8_t *)get_ip_hdr + sizeof(sr_ip_hdr_t));
    mapping_type = nat_mapping_tcp;
    aux_ext = ntohs(get_tcp_hdr->tcp_dst_port);
  } else {
    return NULL;
  }

  return sr_nat_lookup_external(&(sr->nat), aux_ext, mapping_type);
}

/* return the mapping if an internal (ip, port) pair has a mapping to an external
 * address. MUST FREE the returned structure if it isn't NULL. */
struct sr_nat_mapping *find_internal_mapping(struct sr_instance* sr, uint8_t* buf) {

  sr_ip_hdr_t *get_ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
  uint16_t aux_int;
  sr_nat_mapping_type mapping_type;

  if(get_ip_hdr->ip_p == ip_protocol_icmp) {
    sr_icmp_hdr_t *get_icmp_hdr = (sr_icmp_hdr_t *)((uint8_t*)get_ip_hdr + sizeof(sr_ip_hdr_t));
    if(get_icmp_hdr->icmp_type != 0x08 && get_icmp_hdr->icmp_code != 0x08)
      return NULL;
    mapping_type = nat_mapping_icmp;
    aux_int = get_icmp_hdr->icmp_id;
  } else if (get_ip_hdr->ip_p == ip_protocol_tcp) {
    sr_tcp_hdr_t *get_tcp_hdr = (sr_tcp_hdr_t *)((uint8_t*)get_ip_hdr + sizeof(sr_ip_hdr_t)); 
    mapping_type = nat_mapping_tcp;
    aux_int = get_tcp_hdr->tcp_src_port;
  } else {
    return NULL;
  }

  return sr_nat_lookup_internal(&(sr->nat), get_ip_hdr->ip_src, aux_int, mapping_type);
}

uint16_t tcp_cksum(sr_tcp_hdr_t *tcp_hdr, sr_ip_hdr_t *ip_hdr) {
  tcp_hdr->tcp_cksum = 0x0000;
  struct tcp_pseudo_hdr pseudo_hdr;
  pseudo_hdr.ip_src = ip_hdr->ip_src;
  pseudo_hdr.ip_dst = ip_hdr->ip_dst;
  pseudo_hdr.zero = 0x00;
  pseudo_hdr.ptcl = 0x06;
  pseudo_hdr.len = htons(ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));
  void* concat_hdrs = malloc(ntohs(pseudo_hdr.len) + sizeof(struct tcp_pseudo_hdr));
  memcpy(concat_hdrs, &pseudo_hdr, sizeof(struct tcp_pseudo_hdr));
  memcpy((uint8_t*)concat_hdrs + sizeof(struct tcp_pseudo_hdr), tcp_hdr, ntohs(pseudo_hdr.len));
  uint16_t checksum = cksum(concat_hdrs, ntohs(pseudo_hdr.len) + sizeof(struct tcp_pseudo_hdr));
  free(concat_hdrs);
  return checksum;
}

void handle_nat_ip_packet(struct sr_instance *sr, uint8_t* buf, unsigned int len, char* interface) {
  sr_ethernet_hdr_t *get_eth_hdr = (sr_ethernet_hdr_t *)(buf);
  sr_ip_hdr_t *get_ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));

  struct sr_if *outgoing_iface = find_if_from_ip(sr, get_ip_hdr->ip_dst);
  if(outgoing_iface) { /* packet's destination IP is one of the router's. */
    sr_print_if(outgoing_iface);
    struct sr_nat_mapping *mapping_ext = find_external_mapping(sr, buf);
    if(!mapping_ext) {
    /* no mapping for the PORT or ICMP ID external -> packet is addressed to the NAT. */
      fprintf(stderr, "[NAT] Packet is addressed to the NAT\n");
      handle_ip_packet_for_router(sr, buf, len, interface);
      return;
    }
    /* Case: found a mapping for the (ip, port) pair: 
     * Rewrite packet */
    get_ip_hdr->ip_dst = mapping_ext->ip_int;
    get_ip_hdr->ip_ttl--;
    get_ip_hdr->ip_sum = 0;
    get_ip_hdr->ip_sum = cksum(get_ip_hdr, sizeof(sr_ip_hdr_t));
    if(mapping_ext->type == nat_mapping_icmp) {
      sr_icmp_hdr_t *get_icmp_hdr = (sr_icmp_hdr_t *)((uint8_t *)get_ip_hdr + sizeof(sr_ip_hdr_t));
      get_icmp_hdr->icmp_id = mapping_ext->aux_int;
      get_icmp_hdr->icmp_sum = 0;
      get_icmp_hdr->icmp_sum = cksum(get_icmp_hdr, ntohs(get_ip_hdr->ip_len) - get_ip_hdr->ip_hl*4);
    } else if (mapping_ext->type == nat_mapping_tcp) {
      sr_tcp_hdr_t *get_tcp_hdr = (sr_tcp_hdr_t *)((uint8_t *)get_ip_hdr + sizeof(sr_ip_hdr_t));
      get_tcp_hdr->tcp_dst_port = mapping_ext->aux_int;
      /* TODO: Unsolicited SYN packet */
      if((get_tcp_hdr->tcp_flags & TCP_SYN) && !(get_tcp_hdr->tcp_flags & TCP_ACK)) {
        free(mapping_ext);
        return;
      }
      get_tcp_hdr->tcp_cksum = 0;
      get_tcp_hdr->tcp_cksum = tcp_cksum(get_tcp_hdr, get_ip_hdr);
    }

    /* Forward packet, or queue it if no ARP entry matched */
    struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), get_ip_hdr->ip_dst);
    if(entry) { /* Found match in ARP cache -> forward packet */
      struct sr_if *internal_if = sr_get_interface(sr, "eth1");
      memcpy(get_eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
      memcpy(get_eth_hdr->ether_shost, internal_if->addr, ETHER_ADDR_LEN);
      sr_send_packet(sr, buf, len, "eth1");
      free(entry);
    } else { /* No match in ARP cache -> queue packet. */
      sr_arpcache_queuereq(&(sr->cache), get_ip_hdr->ip_dst, buf, len, "eth1");
    }
    free(mapping_ext);
    return;
  } /* End of case when the packet's destination IP is one of the router's IP. */

  struct sr_rt *rt = longest_prefix_match(sr, get_ip_hdr->ip_dst);
  if(!rt) { /* no matching entry in routing table */
    send_icmp_exception(sr, get_ip_hdr->ip_src, get_eth_hdr->ether_shost, htons(get_ip_hdr->ip_id) + 1,
            buf + sizeof(sr_ethernet_hdr_t), htons(get_ip_hdr->ip_len), DEST_NET_UNREACHABLE);
    return;
  }

  /* Case: found a match in routing table */
  if(strcmp(interface, "eth1") == 0) {/* check that the packet came from an internal source */
    if(strcmp(rt->interface, "eth1") == 0) { /* outgoing interface is also the internal interface */
      return;
    }
    /* Now, the packet is originating from an internal source and destined for an external destination. */
    struct sr_if* ext_iface = sr_get_interface(sr, rt->interface); 
    struct sr_nat_mapping *mapping_int = find_internal_mapping(sr, buf);
    sr_tcp_hdr_t *get_tcp_hdr = (sr_tcp_hdr_t *)((uint8_t*)get_ip_hdr + sizeof(sr_ip_hdr_t));
    sr_icmp_hdr_t *get_icmp_hdr = (sr_icmp_hdr_t *)((uint8_t*)get_ip_hdr + sizeof(sr_ip_hdr_t));
    if(!mapping_int) { /* no mapping -> create one. */
      sr_nat_mapping_type mapping_type;
      uint16_t aux_int;
      if(get_ip_hdr->ip_p == ip_protocol_icmp) {
        mapping_type = nat_mapping_icmp;
        aux_int = get_icmp_hdr->icmp_id;
      } else if (get_ip_hdr->ip_p == ip_protocol_tcp) {
        mapping_type = nat_mapping_tcp;
        aux_int = get_tcp_hdr->tcp_src_port;
      }
      mapping_int = sr_nat_insert_mapping(&(sr->nat), ext_iface->ip, get_ip_hdr->ip_src, aux_int, mapping_type);
#ifdef  DEBUG_ENABLE
      fprintf(stderr, "New mapping inserted, NAT mapping table: \n");
      print_nat_table(&(sr->nat));
#endif
    }

    /* Rewrite headers */
    get_ip_hdr->ip_src = ext_iface->ip;
    get_ip_hdr->ip_ttl--;
    get_ip_hdr->ip_sum = 0;
    get_ip_hdr->ip_sum = cksum(get_ip_hdr, sizeof(sr_ip_hdr_t));
    if(mapping_int->type == nat_mapping_icmp) {
      get_icmp_hdr->icmp_id = htons(mapping_int->aux_ext);
      get_icmp_hdr->icmp_sum = 0;
      get_icmp_hdr->icmp_sum = cksum(get_icmp_hdr, ntohs(get_ip_hdr->ip_len) - get_ip_hdr->ip_hl*4);
    } else if (mapping_int->type == nat_mapping_tcp) {
      get_tcp_hdr->tcp_src_port = htons(mapping_int->aux_ext);
      get_tcp_hdr->tcp_cksum = 0;
      get_tcp_hdr->tcp_cksum = tcp_cksum(get_tcp_hdr, get_ip_hdr);
    }
    /* Forward packet, or queue it if no ARP entry is returned */
    struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), get_ip_hdr->ip_dst);
    if(entry) {
      memcpy(get_eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
      memcpy(get_eth_hdr->ether_shost, ext_iface->addr, ETHER_ADDR_LEN);
      sr_send_packet(sr, buf, len, ext_iface->name);
      free(entry);
    } else { /* No match in ARP cache --> queue packet */
#ifdef  DEBUG_ENABLE
      fprintf(stderr, "[NAT] MAC not found in ARP cache, queuing packet to requests list and handle...\n");
#endif
      sr_arpcache_queuereq(&(sr->cache), get_ip_hdr->ip_dst, buf, len, ext_iface->name);
    }
    free(mapping_int);
    return;
  } /* End case when incoming interface is the internal interface */

  /* Case: Incoming iface is not 'eth1' (it's also the case that dst IP is not the router')*/
  forward_packet(sr, buf, len);
}


