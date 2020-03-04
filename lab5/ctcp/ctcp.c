/******************************************************************************
 * ctcp.c
 * ------
 * Implementation of cTCP done here. This is the only file you need to change.
 * Look at the following files for references and useful functions:
 *   - ctcp.h: Headers for this file.
 *   - ctcp_iinked_list.h: Linked list functions for managing a linked list.
 *   - ctcp_sys.h: Connection-related structs and functions, cTCP segment
 *                 definition.
 *   - ctcp_utils.h: Checksum computation, getting the current time.
 *
 *****************************************************************************/

#include "ctcp.h"
#include "ctcp_linked_list.h"
#include "ctcp_sys.h"
#include "ctcp_utils.h"

#undef ENABLE_DEBUG

typedef struct {
  uint32_t num_retransmits; /* number of retransmission */
  long timestamp_of_last_send; /* timestamp of last send */
  ctcp_segment_t ctcp_segment; /* ctcp_segment struct */
} wrapped_ctcp_segment_t;

typedef struct {
  uint32_t last_seqno_accepted; /* to generate ackno-s when sending */
  uint32_t num_truncated_segments;
  uint32_t num_out_of_window_segments;
  uint32_t num_invalid_cksum;
  linked_list_t *segments_output; /* linked list of ctcp_segment_t*'s */
  bool FIN_was_recv;
} rx_state_t;

typedef struct {
  uint32_t last_ackno_received;
  uint32_t last_seqno_read; /* LAST byte read from conn_input(). */
  linked_list_t *wrapped_unacked_segments; /* point to wrapped_ctcp_segment_t 
                                            * list of unacknowledged segments. */
  bool EOF_was_read;
} tx_state_t;

/**
 * Connection state.
 *
 * Stores per-connection information such as the current sequence number,
 * unacknowledged packets, etc.
 *
 * You should add to this to store other fields you might need.
 */
struct ctcp_state {
  struct ctcp_state *next;  /* Next in linked list */
  struct ctcp_state **prev; /* Prev in linked list */

  conn_t *conn;             /* Connection object -- needed in order to figure
                               out destination when sending */

  /* FIXME: Add other needed fields. */
  long FIN_WAIT_time_start;
  ctcp_config_t ctcp_config;
  tx_state_t tx_state;
  rx_state_t rx_state;
};

/**
 * Linked list of connection states. Go through this in ctcp_timer() to
 * resubmit segments and tear down connections.
 */
static ctcp_state_t *state_list;

/* FIXME: Feel free to add as many helper functions as needed. Don't repeat
          code! Helper functions make the code clearer and cleaner. */
void ctcp_send_segment(ctcp_state_t *state, wrapped_ctcp_segment_t* wrapped_segment)
{
  int bytes_sent;

  if(wrapped_segment->num_retransmits >= 6) { /* maximum retransmission */
    wrapped_segment->num_retransmits = 0;
    ctcp_destroy(state);
    return;
  }
  /* build segment's ctcp header fields. */
  wrapped_segment->ctcp_segment.ackno = htonl(state->rx_state.last_seqno_accepted + 1);
  wrapped_segment->ctcp_segment.flags |= TH_ACK;
  wrapped_segment->ctcp_segment.window = htons(state->ctcp_config.recv_window);
  wrapped_segment->ctcp_segment.cksum = 0;
  wrapped_segment->ctcp_segment.cksum = 
    cksum(&wrapped_segment->ctcp_segment, ntohs(wrapped_segment->ctcp_segment.len));

  bytes_sent = conn_send(state->conn, &wrapped_segment->ctcp_segment, 
                          ntohs(wrapped_segment->ctcp_segment.len));
  wrapped_segment->timestamp_of_last_send = current_time(); /* get time immediately when sending */
  wrapped_segment->num_retransmits++;
  if(bytes_sent < ntohs(wrapped_segment->ctcp_segment.len)) {
    fprintf(stderr, "-----CONN_SEND returned %d bytes instead of %d\n",
                    bytes_sent, ntohs(wrapped_segment->ctcp_segment.len));
    return; /* conn_send failed */
  }
  #ifdef ENABLE_DEBUG
  fprintf(stderr, "-----CONN_SEND: ");
  print_segment_ctcp(&wrapped_segment->ctcp_segment);
  #endif
}

void ctcp_send_all(ctcp_state_t* state) {
  wrapped_ctcp_segment_t *wrapped_segment;
  long ms_since_last_send;
  unsigned int i, num_unacked_segments;
  uint32_t last_seqno_of_segment, last_allow_seqno;
  ll_node_t *current_node;

  if(state == NULL)   
    return;

  if((num_unacked_segments = state->tx_state.wrapped_unacked_segments->length) == 0)
    return;
  #ifdef ENABLE_DEBUG
    fprintf(stderr, "number of unacked segments: %d\n", num_unacked_segments);
  #endif
  for(i = 0; i < num_unacked_segments; ++i) {
    if (i == 0) {
      current_node = ll_front(state->tx_state.wrapped_unacked_segments);
    } else {
      current_node = current_node->next;
    }
    wrapped_segment = (wrapped_ctcp_segment_t*)current_node->object;

    /* calculating sequence number of last byte of segment */
    last_seqno_of_segment = ntohl(wrapped_segment->ctcp_segment.seqno) +
        ntohs(wrapped_segment->ctcp_segment.len) - sizeof(ctcp_segment_t) - 1;
    /* calculating allowable sequence number (do not out of window) */
    last_allow_seqno = state->tx_state.last_ackno_received - 1 //need last byte received
                              + state->ctcp_config.send_window;
    if(state->tx_state.last_ackno_received == 0) {
      ++last_allow_seqno; /* last_ackno_received starts at 0 */
    }
    /* Last Sequence Sent - Last ACK Received <= Sliding Window Size */
    if(last_seqno_of_segment > last_allow_seqno) {
      fprintf(stderr, "last seqno of data=%u last allowable seqno=%u\n",
        last_seqno_of_segment, last_allow_seqno);
      return;
    }
    // This segment is within the send window. Any segments here that have not been sent  
    // can now be sent. The first segment can be retransmitted if it timed out
    if(wrapped_segment->num_retransmits == 0) {
      ctcp_send_segment(state, wrapped_segment);
    } else if (i == 0) {
      /* check & see if we need to retransmits the first segment */
      ms_since_last_send = current_time() - wrapped_segment->timestamp_of_last_send;
      if(ms_since_last_send > state->ctcp_config.rt_timeout) { /* Time out, resend */
        ctcp_send_segment(state, wrapped_segment);
      }
    }
  }
}

void ctcp_send_ack(ctcp_state_t *state) {
  ctcp_segment_t *segment = calloc(1, sizeof(ctcp_segment_t));
  segment->seqno = 0; /* dont care seqno */
  segment->ackno = htonl(state->rx_state.last_seqno_accepted + 1);
  segment->len = ntohs((uint16_t)sizeof(ctcp_segment_t));
  segment->flags |= TH_ACK;
  segment->window = htons(state->ctcp_config.recv_window);
  segment->cksum = 0;
  segment->cksum = cksum(segment, sizeof(ctcp_segment_t));
  conn_send(state->conn, segment, sizeof(ctcp_segment_t));
  #ifdef ENABLE_DEBUG
  fprintf(stderr, "-----ctcp_send_ack: \n");
  print_hdr_ctcp(segment);
  #endif
}

void ctcp_clear_unacked_segments(ctcp_state_t *state) {
  ll_node_t *front_node;
  wrapped_ctcp_segment_t *wrapped_segment;
  uint16_t datalen;
  uint32_t last_seqno_of_data;

  while(ll_length(state->tx_state.wrapped_unacked_segments) > 0) {
    front_node = ll_front(state->tx_state.wrapped_unacked_segments);
    wrapped_segment = (wrapped_ctcp_segment_t *) front_node->object;
    datalen = ntohs(wrapped_segment->ctcp_segment.len) - sizeof(ctcp_segment_t);
    last_seqno_of_data = ntohl(wrapped_segment->ctcp_segment.seqno) + datalen - 1;

    if(last_seqno_of_data < state->tx_state.last_ackno_received) {
      /* this segment has been ack-ed */
      #ifdef ENABLE_DEBUG
      fprintf(stderr, "ctcp_clear_unacked_segments #seq: %u\n", ntohl(wrapped_segment->ctcp_segment.seqno));
      #endif
      free(wrapped_segment);
      ll_remove(state->tx_state.wrapped_unacked_segments, front_node);
    } else {
      return; /* segment has not been ack-ed. Done! */
    }
  }
}

ctcp_state_t *ctcp_init(conn_t *conn, ctcp_config_t *cfg) {
  /* Connection could not be established. */
  if (conn == NULL) {
    return NULL;
  }

  /* Established a connection. Create a new state and update the linked list
     of connection states. */
  ctcp_state_t *state = calloc(sizeof(ctcp_state_t), 1);
  state->next = state_list;
  state->prev = &state_list;
  if (state_list)
    state_list->prev = &state->next;
  state_list = state;

  /* Set fields. */
  state->conn = conn;
  /* FIXME: Do any other initialization here. */
  state->FIN_WAIT_time_start = 0;
  /* ctcp_config */
  state->ctcp_config.recv_window = cfg->recv_window;
  state->ctcp_config.send_window = cfg->send_window;
  state->ctcp_config.timer = cfg->timer;
  state->ctcp_config.rt_timeout = cfg->rt_timeout;
  #ifdef ENABLE_DEBUG
  fprintf(stderr, "Receive window           : %d (bytes)\n", state->ctcp_config.recv_window);
  fprintf(stderr, "Send window              : %d (bytes)\n", state->ctcp_config.send_window);
  fprintf(stderr, "Timer interval           : %d (ms)\n", state->ctcp_config.timer);
  fprintf(stderr, "Retransmission interval  : %d (ms)\n", state->ctcp_config.rt_timeout);
  #endif
  /* tx_state */
  state->tx_state.last_ackno_received = 0; /* last acknowledgememt number of tx state */
  state->tx_state.last_seqno_read = 1; /* last byte read from input */
  state->tx_state.EOF_was_read = false;
  state->tx_state.wrapped_unacked_segments = ll_create(); /* list of unack-ed segments */
  /* rx_state */
  state->rx_state.last_seqno_accepted = 0; /* last byte of received segment */
  state->rx_state.num_truncated_segments = 0;
  state->rx_state.num_out_of_window_segments = 0;
  state->rx_state.num_invalid_cksum = 0;
  state->rx_state.FIN_was_recv = false;
  state->rx_state.segments_output = ll_create(); /* list of output segments */

  free(cfg);
  return state;
}

void ctcp_destroy(ctcp_state_t *state) {
  /* Update linked list. */
  if (state->next)
    state->next->prev = state->prev;

  *state->prev = state->next;
  conn_remove(state->conn);

  /* FIXME: Do any other cleanup here. */
  #ifdef ENABLE_DEBUG
  fprintf(stderr, "Number of invalid checksum segments: %d\n"
                  "Number of truncated segments       : %d\n"
                  "Number of out of window segments   : %d\n"
                  "Number of unack-ed wrapped segments: %d\n"
                  "Number of segments weren't outputed: %d\n", 
                  state->rx_state.num_invalid_cksum,
                  state->rx_state.num_truncated_segments,
                  state->rx_state.num_out_of_window_segments,
                  ll_length(state->tx_state.wrapped_unacked_segments),
                  ll_length(state->rx_state.segments_output));
  #endif

  ll_node_t *front_node;
  fprintf(stderr, "Freeing segments in unack-ed list... ");
  /* free all segments in unack-ed list */
  while(ll_length(state->tx_state.wrapped_unacked_segments) > 0) {
    front_node = ll_front(state->tx_state.wrapped_unacked_segments);
    free(front_node->object);
    ll_remove(state->tx_state.wrapped_unacked_segments, front_node);
  }
  ll_destroy(state->tx_state.wrapped_unacked_segments);

  fprintf(stderr, "done!\nFreeing segments in output list... ");
  /* free all segments in segments_output list */
  while(ll_length(state->rx_state.segments_output) > 0) {
    front_node = ll_front(state->rx_state.segments_output);
    free(front_node->object);
    ll_remove(state->rx_state.segments_output, front_node);
  }
  ll_destroy(state->rx_state.segments_output);
  fprintf(stderr, "done!\n");

  free(state);
  end_client();
}

void ctcp_read(ctcp_state_t *state) {
  /* FIXME */
  uint8_t buf[MAX_SEG_DATA_SIZE];
  int bytes_read;
  wrapped_ctcp_segment_t *wrapped_segment;

  if(state->tx_state.EOF_was_read)
    return;
  /* Input this way will handle LARGE + BINARY file */
  while((bytes_read = conn_input(state->conn, buf, MAX_SEG_DATA_SIZE)) > 0) {
    fprintf(stderr, "-----CONN_INPUT Read %d bytes\n", bytes_read);
    wrapped_segment = (wrapped_ctcp_segment_t*) calloc(1,
                              sizeof(wrapped_ctcp_segment_t) + bytes_read);
    /* segment's length, sequence number, data[] */
    wrapped_segment->ctcp_segment.len = htons((uint16_t) sizeof(ctcp_segment_t) + bytes_read);
    wrapped_segment->ctcp_segment.seqno = htonl(state->tx_state.last_seqno_read);
    memcpy(wrapped_segment->ctcp_segment.data, buf, bytes_read);
    /* update seqno tx state. Sequence numbers start at 1, not 0. */
    state->tx_state.last_seqno_read += bytes_read; 
    /* add new ctcp segment to list of unacknowledged segments. */
    ll_add(state->tx_state.wrapped_unacked_segments, wrapped_segment);
  }

  if(bytes_read == -1) { // get EOF
    fprintf(stderr, "----- FIN_WAIT_1 -----\n");
    state->tx_state.EOF_was_read = true;
    /* Create a FIN segment */
    wrapped_segment = (wrapped_ctcp_segment_t*) calloc(1,
                              sizeof(wrapped_ctcp_segment_t));
    wrapped_segment->ctcp_segment.len = htons((uint16_t) sizeof(ctcp_segment_t));
    wrapped_segment->ctcp_segment.seqno = htonl(state->tx_state.last_seqno_read);
    wrapped_segment->ctcp_segment.flags |= TH_FIN; // FIN in network
    ll_add(state->tx_state.wrapped_unacked_segments, wrapped_segment);
  }
  ctcp_send_all(state_list);
}

void ctcp_receive(ctcp_state_t *state, ctcp_segment_t *segment, size_t len) {
  /* FIXME */
  uint16_t recv_cksum, datalen;
  uint32_t last_seqno_of_data, largest_allow_seqno, smallest_allow_seqno;
  ll_node_t *temp_node;
  ctcp_segment_t *tmp_segment;
  unsigned int i, length_of_segment_output_list;

  #ifdef ENABLE_DEBUG
  fprintf(stderr, "-----CTCP_RECEIVE: ");
  print_hdr_ctcp(segment);
  #endif
  /* segment was truncated */
  if(len < ntohs(segment->len)) { 
    free(segment);
    state->rx_state.num_truncated_segments++;
    return;
  }
  /* checksum */
  recv_cksum = segment->cksum;
  segment->cksum = 0;
  segment->cksum = cksum(segment, ntohs(segment->len));
  if(recv_cksum != segment->cksum) {
    fprintf(stderr, "Invalid checksum! Receive: 0x%04x, Compute: 0x%04x ",
            recv_cksum, segment->cksum);
    free(segment);
    state->rx_state.num_invalid_cksum++;
    return;
  }
  /* handle receive window size */
  datalen = ntohs(segment->len) - sizeof(ctcp_segment_t);
  if(datalen) {
    /* seqno of last data byte of segment */
    last_seqno_of_data = ntohl(segment->seqno) + datalen - 1; 
    smallest_allow_seqno = state->rx_state.last_seqno_accepted + 1;
    largest_allow_seqno = smallest_allow_seqno +
                          state->ctcp_config.recv_window - 1;
    /* segment out of window */
    if(last_seqno_of_data > largest_allow_seqno || 
        ntohl(segment->seqno) < smallest_allow_seqno) { 
      free(segment);
      ctcp_send_ack(state); /* send the sender our state */
      state->rx_state.num_out_of_window_segments++;
      fprintf(stderr, "#seq%d OUT OF WINDOW\n", ntohl(segment->seqno));
      return;
    }
  }

  fprintf(stderr, "Got a valid segment with %d byte of data:%c", datalen,
       datalen == 0 ? '\n' : ' ');
  
  /* handle if segment was ACKed, then it used to be clear unack-ed segments later */
  if(segment->flags & TH_ACK) {
    state->tx_state.last_ackno_received = ntohl(segment->ackno);
  }
  /* add segment to segments_output list in sorted order. Only output data if  
   * segment has not empty, or receive a FIN (which case we'll need to output EOF)
   */
  if(datalen || segment->flags & TH_FIN) {
    /* taking care to throw away/free it if it's a duplicate */
    length_of_segment_output_list = ll_length(state->rx_state.segments_output);
    if(length_of_segment_output_list == 0)
      ll_add(state->rx_state.segments_output, segment);
    else if (length_of_segment_output_list == 1) {
      temp_node = ll_front(state->rx_state.segments_output);
      tmp_segment = (ctcp_segment_t*) temp_node->object;
      if(ntohl(segment->seqno) == ntohl(tmp_segment->seqno))
        free(segment); /* duplicate, throw away */
      else if (ntohl(segment->seqno) > ntohl(tmp_segment->seqno))
        ll_add(state->rx_state.segments_output, segment); /* new segment */
      else 
        ll_add_front(state->rx_state.segments_output, segment); /* come earlier */
    } else {
      ctcp_segment_t *first_segment;
      ctcp_segment_t *last_segment;
      ll_node_t *first_node;
      ll_node_t *last_node;

      first_node = ll_front(state->rx_state.segments_output);
      last_node = ll_back(state->rx_state.segments_output);
      first_segment = (ctcp_segment_t *) first_node->object;
      last_segment = (ctcp_segment_t *) last_node->object;

      if(ntohl(segment->seqno) > ntohl(last_segment->seqno)) 
        ll_add(state->rx_state.segments_output, segment);
      else if (ntohl(segment->seqno) < ntohl(first_segment->seqno))
        ll_add_front(state->rx_state.segments_output, segment);
      else {
        for(i = 0; i < length_of_segment_output_list - 1; ++i) {
          ll_node_t *cur_node;
          ll_node_t *next_node;
          ctcp_segment_t *cur_segment;
          ctcp_segment_t *next_segment;

          if(i == 0)
            cur_node = ll_front(state->rx_state.segments_output);
          else
            cur_node = cur_node->next;
          
          next_node = cur_node->next;
          cur_segment = (ctcp_segment_t *) cur_node->object;
          next_segment = (ctcp_segment_t *) next_node->object;
          /* check for duplicate */
          if((ntohl(segment->seqno) == ntohl(cur_segment->seqno)) ||
             (ntohl(segment->seqno) == ntohl(next_segment->seqno))) {
            free(segment);
            break;
          } else {
            /* add node between two nodes */
            if((ntohl(segment->seqno) > ntohl(cur_segment->seqno)) &&
               (ntohl(segment->seqno) < ntohl(next_segment->seqno))) {
              ll_add_after(state->rx_state.segments_output, cur_node, segment);
              break;
            }
          }
        }
      }
    }
  } /* End of condition datalen || TH_FIN */

  ctcp_output(state); /* output all received segments */
  ctcp_clear_unacked_segments(state);
}

void ctcp_output(ctcp_state_t *state) {
  /* FIXME */
  ll_node_t *front_node;
  ctcp_segment_t *segment;
  int datalen, num_segments_output = 0;

  if(state == NULL) return;
  while(ll_length(state->rx_state.segments_output) > 0) {
    front_node = ll_front(state->rx_state.segments_output);
    segment = (ctcp_segment_t *) front_node->object;
    datalen = ntohs(segment->len) - sizeof(ctcp_segment_t);

    if(datalen > 0) {
      if(ntohl(segment->seqno) != state->rx_state.last_seqno_accepted + 1)
        return; /* Wrong order segment or hole in segments_output list */
      if(conn_bufspace(state->conn) < datalen)
        return; /* not enough space to output */
      if(conn_output(state->conn, segment->data, datalen) == -1) 
        return; /* conn_output failed */
      
      ++num_segments_output;
      state->rx_state.last_seqno_accepted += datalen;
    }
  
    if((!state->rx_state.FIN_was_recv) && (segment->flags & TH_FIN)) {
      fprintf(stderr, "Received FIN_WAIT_1\n");
      state->rx_state.FIN_was_recv = true;
      state->rx_state.last_seqno_accepted++;
      conn_output(state->conn, segment->data, 0); /* output EOF to STDOUT */
      ++num_segments_output;
    }
    /* successfully output the segment, remove from linked list output*/
    free(segment);
    ll_remove(state->rx_state.segments_output, front_node);
  } /* End while loop */
  
  if(num_segments_output) {
    ctcp_send_ack(state); /* send ACK */
  }
}

void ctcp_timer() {
  /* FIXME */
  if(state_list == NULL)    
    return;
  ctcp_output(state_list);
  ctcp_send_all(state_list);

  if( (state_list->tx_state.EOF_was_read) &&
      (state_list->rx_state.FIN_was_recv) &&
      (ll_length(state_list->tx_state.wrapped_unacked_segments) == 0) &&
      (ll_length(state_list->rx_state.segments_output) == 0) ) {
    if(state_list->FIN_WAIT_time_start == 0) {
      state_list->FIN_WAIT_time_start = current_time();
    } else if (current_time() - state_list->FIN_WAIT_time_start > 2*1000) {
      ctcp_destroy(state_list);
    }
  }
}
