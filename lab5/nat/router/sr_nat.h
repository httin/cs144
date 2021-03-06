
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp,
  nat_mapping_udp,
} sr_nat_mapping_type;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  uint32_t ip; /* External destination. In host endianness */
  uint32_t port; /* External destination. In host endianness */
  int syn;
  int syn_ack;
  int conn_established; /* True if the connection is established. False if in transitory state. */
  time_t last_updated; /* Used for both timeouts */

  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  uint16_t port; /* for TCP mapping */
  uint16_t identifier; /* for ICMP mapping */

  int icmp_query_timeout; /* ICMP query timeout interval in seconds (default to 60) */
  int tcp_established_timeout; /* TCP Established Idle Timeout in seconds (default to 7440) */
  int tcp_transitory_timeout; /* TCP Transitory Idle Timeout in seconds (default to 300) */

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */
void print_nat_table(struct sr_nat *nat);

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_ext, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type);


#endif
