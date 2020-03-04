#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include <unistd.h>

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */
  nat->port = 1024;
  nat->identifier = 0;

  return success;
}

void print_nat_table(struct sr_nat *nat) {
  struct sr_nat_mapping *map = nat->mappings;
  struct in_addr ip_int;
  fprintf(stderr, "\nTYPE\tIP internal\tPort internal\tPort external\tUPDATED\n");
  fprintf(stderr, "-------------------------------------------------------------------------------\n");
  while(map != NULL) {
    ip_int.s_addr = map->ip_int;
    fprintf(stderr, "%s\t%s\t%u\t\t%u\t\t%.24s\n", 
        map->type == nat_mapping_icmp ? "ICMP" : "TCP",
        inet_ntoa(ip_int),
        ntohs(map->aux_int),   /* network byte order */
        ntohs(map->aux_ext),   /* network byte order */
        ctime(&(map->last_updated)));

    map = map->next;
  }
}

int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));
}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
    /* we need 2 nodes of linked list to maintain the link after freeing a node */
    struct sr_nat_mapping *mapping = nat->mappings;
    struct sr_nat_mapping *prev = nat->mappings;
    int end_of_mapping = 0;
    while(mapping) {
      mapping = mapping->next;
      if(mapping == NULL) {
        mapping = prev;
        end_of_mapping = 1;
      }
      if(mapping->type == nat_mapping_icmp) {
        if(difftime(curtime, mapping->last_updated) > nat->icmp_query_timeout) {
          struct sr_nat_mapping *to_free = mapping;
          fprintf(stderr, "[expire mapping] type: icmp, aux_ext: %u\n", to_free->aux_ext);
          mapping = mapping->next;
          free(to_free);
          prev->next = mapping;
          continue;
        }
      } else if (mapping->type == nat_mapping_tcp) {
#ifdef FUCK
        struct sr_nat_connection *conn = mapping->conns;
        struct sr_nat_connection *prev_conn = mapping->conns;
        while(conn) {
          conn = conn->next;
          if(conn == NULL) 
            conn = prev_conn;

          time_t timeout;
          if(conn->conn_established) {
            timeout = nat->tcp_established_timeout;
          } else {
            timeout = nat->tcp_transitory_timeout;
          }
          if(difftime(curtime, conn->last_updated) > timeout) {
            struct sr_nat_connection *to_free = conn;
            conn = conn->next;
            free(to_free);
            prev_conn->next = conn;
            continue;
          }
          prev_conn = prev_conn->next;
        }
        if(mapping->conns == NULL) { /* Cleared out all connections for mapping. */
          struct sr_nat_mapping *to_free = mapping;
          fprintf(stderr, "[expire mapping] type: tcp, aux_ext: %u\n", to_free->aux_ext);
          mapping = mapping->next;
          free(to_free);
          prev->next = mapping;
          continue;
        }
#endif
      }
      if(end_of_mapping)    
        mapping = NULL; /* End while loop */
      prev = prev->next;
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *mapping = NULL;
  for(mapping = nat->mappings; mapping != NULL; mapping = mapping->next) {
    if(mapping->type != type)
      continue;

    if(mapping->aux_ext == aux_ext) {
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
      if(type == nat_mapping_icmp) {
        mapping->last_updated = time(NULL);
      }
      break;
    }
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *mapping = NULL;
  for(mapping = nat->mappings; mapping != NULL; mapping = mapping->next) {
    if(mapping->type != type)
      continue;

    if(mapping->ip_int == ip_int && mapping->aux_int == aux_int) {
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
      if(type == nat_mapping_icmp) {
        mapping->last_updated = time(NULL);
      }
      break;
    }
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_ext, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
  mapping->type = type;
  mapping->ip_int = ip_int; /* internal IP */
  mapping->ip_ext = ip_ext;
  mapping->aux_int = aux_int; /* internal ICMP_ID or port */
  mapping->last_updated = time(NULL);
  if(type == nat_mapping_icmp) {
    mapping->conns = NULL;
    mapping->aux_ext = nat->identifier; /* external ICMP_ID */
    nat->identifier++;
    fprintf(stderr, "[alloc mapping] type: icmp, aux_ext: %u\n", mapping->aux_ext);
  } else if (type == nat_mapping_tcp) {
    mapping->conns = NULL;
    if(nat->port < 1024)
      nat->port = 1024;
    mapping->aux_ext = nat->port; /* external PORT */
    nat->port++;
    fprintf(stderr, "[alloc mapping] type: tcp, aux_ext: %u\n", mapping->aux_ext);
  }
  /* Add node to head of list */
  mapping->next = nat->mappings;
  nat->mappings = mapping;
  /* make a copy for returning */
  struct sr_nat_mapping *copy = malloc(sizeof(struct sr_nat_mapping));
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}
