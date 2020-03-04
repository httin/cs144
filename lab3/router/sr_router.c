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

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
#include <arpa/inet.h>

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
void build_ethernet_hdr(uint8_t* buf, uint8_t dhost[], uint8_t shost[], uint16_t type) {
  sr_ethernet_hdr_t *ethernet = (sr_ethernet_hdr_t *) buf;
  memcpy(ethernet->ether_dhost, dhost, ETHER_ADDR_LEN);
  memcpy(ethernet->ether_shost, shost, ETHER_ADDR_LEN);
  ethernet->ether_type = type;
}

void build_arp_hdr(uint8_t* buf, uint16_t ar_hrd, uint16_t ar_pro, 
                   uint8_t ar_hln, uint8_t ar_pln, uint16_t ar_op,
                   uint8_t *ar_sha, uint32_t ar_sip, uint8_t *ar_tha, uint32_t ar_tip) {
  sr_arp_hdr_t *arp = (sr_arp_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
  arp->ar_hrd = ar_hrd; /* hardware type: Ethernet */
  arp->ar_pro = ar_pro; /* protocol type: IP - 0x0800 */
  arp->ar_hln = ar_hln; /* length of mac */
  arp->ar_pln = ar_pln; /* length of IPv4 */
  arp->ar_op  = ar_op;  /* ARP opcode */
  memcpy(arp->ar_sha, ar_sha, ETHER_ADDR_LEN);  /* source mac */
  arp->ar_sip = ar_sip;                         /* source IP  */
  memcpy(arp->ar_tha, ar_tha, ETHER_ADDR_LEN);  /* target mac */
  arp->ar_tip = ar_tip;                         /* target IP  */
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

void build_icmp_hdr(uint8_t* buf, uint8_t icmp_type, uint8_t icmp_code, 
                    uint8_t ip_hdrlen, uint16_t ip_len) {
  sr_icmp_hdr_t *icmp = (sr_icmp_hdr_t *) (buf +
                            sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  icmp->icmp_type = icmp_type;
  icmp->icmp_code = icmp_code;
  icmp->icmp_unused = 0;
  icmp->icmp_sum  = 0;
  icmp->icmp_sum  = cksum(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
                          ip_len - ip_hdrlen*4);
}

int send_icmp_exception(struct sr_instance* sr, uint32_t dip, uint8_t dmac[ETHER_ADDR_LEN],
         uint16_t ip_id, uint8_t *icmp_data, uint16_t icmp_data_len, int icmp_exeption_type) {
  fprintf(stderr, "Sending ICMP(%lu) packet to ", 34 + sizeof(sr_icmp_hdr_t) + icmp_data_len);
  print_addr_ip_int(ntohl(dip));
   
  struct sr_rt *rt = longest_prefix_match(sr, dip);
  struct sr_if *interface = sr_get_interface(sr, rt->interface);
  
  sr_icmp_hdr_t *icmp;
  uint32_t icmp_len = sizeof(sr_icmp_hdr_t) + icmp_data_len; 
  icmp = malloc(icmp_len); /* contain ip header */
 
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

  icmp->icmp_unused = 0;
  memcpy((uint8_t *)icmp + sizeof(sr_icmp_hdr_t), icmp_data, icmp_data_len);
  icmp->icmp_sum = 0;
  icmp->icmp_sum = cksum(icmp, icmp_len);
  
  uint8_t *buf = calloc(1, 14 + 20 + icmp_len);
  build_ethernet_hdr(buf, dmac, interface->addr, htons(ethertype_ip));
  build_ip_hdr(buf, 5, 4, 0, htons(20 + icmp_len), htons(ip_id), htons(IP_DF), 
               64, ip_protocol_icmp, interface->ip, dip);
  memcpy(buf + 14 + 20, icmp, icmp_len);

  int res = send_pack(sr, dip, buf, 14 + 20 + icmp_len);
  free(icmp);
  free(buf);
  return res;
}

struct sr_if *find_if_from_ip(struct sr_instance* sr, uint32_t get_ip) {
  struct sr_if *if_walker = NULL;
  assert(sr->if_list);
  if_walker = sr->if_list;
  
  while(if_walker) {
    if(if_walker->ip == get_ip) 
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

int forward_packet(struct sr_instance *sr, uint8_t* pac, uint32_t len) {
  uint8_t *buf = malloc(len);
  memcpy(buf, pac, len);

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) buf;
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));

  fprintf(stderr, "Forwarding IP(%"PRIu32") packet to ", len);
  print_addr_ip_int(ntohl(ip_hdr->ip_dst));

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
  } else {
      fprintf(stderr, "MAC not found in ARP cache, queuing to requests list...");
      struct sr_arpreq *req;
      req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, buf, len, rt->interface);
      fprintf(stderr, " done! Handle the request...\n");
      sr_handle_arpreq(sr, req);
      return 0;
  }

  ip_hdr->ip_ttl--;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  int res = send_pack(sr, ip_hdr->ip_dst, buf, len);
  free(buf);
  return res;
}

void arpcache_send_all_packet(struct sr_instance *sr, struct sr_packet *pack) {
  if(pack == NULL)    return;
  
  fprintf(stderr, "Sending packet in queue (");
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pack->buf + sizeof(sr_ethernet_hdr_t));
  fprintf(stderr, "Source: ");
  print_addr_ip_int(ntohl(ip_hdr->ip_src));
  fprintf(stderr, " Target: ");
  print_addr_ip_int(ntohl(ip_hdr->ip_dst));
  fprintf(stderr, " ID: %u)...\n", htons(ip_hdr->ip_id));
    
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
  uint16_t minlength = sizeof(sr_ethernet_hdr_t); /* 14 bytes */ 
  uint8_t *buf = malloc(len);
  memcpy(buf, packet, len); /* make a copy of the packet -> buf */
  sr_ethernet_hdr_t *get_ethhdr = (sr_ethernet_hdr_t *) (buf); /* get ethernet header */
 
  switch(ntohs(get_ethhdr->ether_type)) {
    case ethertype_ip: /* IP = 0x0800 */
      minlength += sizeof(sr_ip_hdr_t); /* 34 bytes */
      if(len < minlength) {
        fprintf(stderr, "IP header insufficient length: packet len=%d minlength=%d",
                len, minlength);
        return;
      }
      /* get IP header */
      sr_ip_hdr_t *get_iphdr = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
      /* verify IP checksum */
      uint16_t get_cksum = get_iphdr->ip_sum;
      get_iphdr->ip_sum = 0;
      get_iphdr->ip_sum = cksum(buf + sizeof(sr_ethernet_hdr_t), get_iphdr->ip_hl*4);
      if(get_cksum != get_iphdr->ip_sum) {
        fprintf(stderr, "[ERROR] Invalid IP checksum! Get: %#x, Compute: %#x\n",
                get_cksum, get_iphdr->ip_sum);
        return;
      }
      /* check destination ip if it is one of the router interfaces --> get it */ 
      if(find_if_from_ip(sr, get_iphdr->ip_dst)) {
        uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));
        if(ip_proto == ip_protocol_icmp) { /* packet has ICMP */
          /* get ICMP header */
          sr_icmp_hdr_t *get_icmphdr = (sr_icmp_hdr_t *) (buf + minlength); 
          minlength += sizeof(sr_icmp_hdr_t); /* 38 bytes */
          /* verify ICMP checksum */
          get_cksum = get_icmphdr->icmp_sum;
          get_icmphdr->icmp_sum = 0;
          get_icmphdr->icmp_sum = cksum(buf + sizeof(sr_ethernet_hdr_t) +
                 sizeof(sr_ip_hdr_t), ntohs(get_iphdr->ip_len) - get_iphdr->ip_hl*4);
          if(get_cksum != get_icmphdr->icmp_sum) {
            fprintf(stderr, "[ERROR] Invalid ICMP checksum! Get: %u, Compute: %u\n",
                    get_cksum, get_icmphdr->icmp_sum);
            return;
          }
          /* check the ICMP message type & code */
          if(get_icmphdr->icmp_type == 8 && get_icmphdr->icmp_code == 0) {
            /* got an ECHO REQUEST message, need to build ECHO REPLY */
            uint8_t *echo_reply = calloc(1, len);
            /* build ethernet header, 14 bytes */
            build_ethernet_hdr(echo_reply, get_ethhdr->ether_shost, 
                               get_ethhdr->ether_dhost, get_ethhdr->ether_type);
            /* build IP header, 20 bytes*/
            build_ip_hdr(echo_reply, 5, 4, 0,
                 get_iphdr->ip_len, get_iphdr->ip_id, get_iphdr->ip_off, 64,
                 ip_protocol_icmp, get_iphdr->ip_dst, get_iphdr->ip_src);
            /* copy the rest of data to echo_reply */
            memcpy(echo_reply + minlength, buf + minlength, len - minlength);
            /* build ICMP header, 4 bytes */
            build_icmp_hdr(echo_reply, 0, 0, get_iphdr->ip_hl, ntohs(get_iphdr->ip_len));
            /* send ICMP reply */
            if(send_pack(sr, get_iphdr->ip_src, echo_reply, len) == 0) {
                free(echo_reply);
            } 
          }
        } else if (ip_proto == ip_protocol_tcp || ip_proto == ip_protocol_udp) {
          /* packet contains a TCP or UDP payload, send an 
             ICMP port unreachable to the sending host */
          send_icmp_exception(sr, get_iphdr->ip_src, get_ethhdr->ether_shost, htons(get_iphdr->ip_id) + 1, 
            buf + sizeof(sr_ethernet_hdr_t), htons(get_iphdr->ip_len), PORT_UNREACHABLE);
        } else { /* ignore the packet */
          return;
        }
      } else { /* IP packet whose destination is not one of the router's interfaces -> forward */
        int res = forward_packet(sr, buf, len);
        if(res != 0) {
          send_icmp_exception(sr, get_iphdr->ip_src, get_ethhdr->ether_shost, htons(get_iphdr->ip_id) + 1, 
                buf + sizeof(sr_ethernet_hdr_t), htons(get_iphdr->ip_len), res);
        }
      } 
      break;    /* End IP Packet */
    case ethertype_arp:/* ARP = 0x0806 */
      minlength += sizeof(sr_arp_hdr_t); /* 42 bytes */
      sr_arp_hdr_t *get_arphdr = (sr_arp_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
      struct sr_if *iface = find_if_from_ip(sr, get_arphdr->ar_tip);
      if(!iface) {
        fprintf(stderr, "Cannot find an interface of address ");
        print_addr_ip_int(ntohl(get_arphdr->ar_tip));
        return;
      }

      if(ntohs(get_arphdr->ar_op) == 1) { /* ARP Request, opcode = 1 */ 
        uint8_t *arp_reply = calloc(1, minlength);
        /* build Ethernet frame */
        build_ethernet_hdr(arp_reply, get_ethhdr->ether_shost, 
                       iface->addr, htons(ethertype_arp));
        /* build ARP Reply frame */
        build_arp_hdr(arp_reply, get_arphdr->ar_hrd, get_arphdr->ar_pro, 
                      6, 4, htons(arp_op_reply), 
                      iface->addr, iface->ip, get_arphdr->ar_sha, get_arphdr->ar_sip);
        /* send arp reply */
        if(!sr_send_packet(sr, arp_reply, minlength, iface->name)) {
          fprintf(stderr, "ARP Reply packet %u bytes sent from %s to ", minlength, iface->name);
          print_addr_ip_int(ntohl(get_arphdr->ar_sip));
          free(arp_reply);
        } else fprintf(stderr, "[ERROR] sr_send_packet ARP Reply FAILED\n");
      } else if (ntohs(get_arphdr->ar_op) == 2) { /* ARP Reply, opcode = 2 */
        struct sr_arpreq *req;
        req = sr_arpcache_insert(&(sr->cache), get_arphdr->ar_sha, get_arphdr->ar_sip);

        fprintf(stderr, "New entry inserted, ARP Cache Table:\n");
        sr_arpcache_dump(&(sr->cache));
        
        if(req != NULL) {    
          arpcache_send_all_packet(sr, req->packets);
          sr_arpreq_destroy(&(sr->cache), req);
        }
      } else {
        fprintf(stderr, "Unrecognize ARP opcode 0x%.4x\n", ntohs(get_arphdr->ar_op));
      } /* End of check ARP opcode */

      break; /* End ARP Packet */
    default:
      fprintf(stderr, "Ethertype %d Invalid!", ntohs(get_ethhdr->ether_type));
  }
}/* end sr_ForwardPacket */

