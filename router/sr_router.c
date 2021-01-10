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

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  /* fill in code here */

  /*#CMP4503 OUR CODE STARTS HERE*/
  printf("#CMP4503 interface: %s\n#", interface);
  print_hdrs(packet);

  switch (ethertype(packet)) {
	  case ethertype_arp:
		  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
		  switch (ntohs(arp_hdr->ar_op)) {
			case arp_op_request:
				if (packet->ar_tip == interface->ip) { 
					/*if request send to our own ip
					turn back with our mac address*/
					printf("#CMP4503 ARP Request received.#")
						uint8_t* replyPacket = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
					sr_ethernet_hdr_t* ethernetHdr = (sr_ethernet_hdr_t*)replyPacket;
					sr_arp_hdr_t* arpHdr = (sr_arp_hdr_t*)(replyPacket + sizeof(sr_ethernet_hdr_t));

					printf("#CMP4503 Sending ARP reply.\n");

					printf("#CMP4503 Filling Ethernet header...\n");
					memcpy(ethernetHdr->ether_dhost, packet->ar_sha, ETHER_ADDR_LEN);
					memcpy(ethernetHdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
					ethernetHdr->ether_type = htons(ethertype_arp);

					printf("#CMP4503 Filling ARP header...\n");
					arpHdr->ar_hrd = htons(arp_hrd_ethernet);
					arpHdr->ar_pro = htons(ethertype_ip);
					arpHdr->ar_hln = ETHER_ADDR_LEN;
					arpHdr->ar_pln = IP_ADDR_LEN;
					arpHdr->ar_op = htons(arp_op_reply);
					memcpy(arpHdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
					arpHdr->ar_sip = interface->ip;
					memcpy(arpHdr->ar_tha, packet->ar_sha, ETHER_ADDR_LEN);
					arpHdr->ar_tip = packet->ar_sip;

					sr_send_packet(sr, replyPacket, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t),
						interface->name);
					printf("#CMP4503 Printing header of the reply packet.\n");
					print_hdrs(packet);
					free(replyPacket);
				} 
				break;
			case arp_op_reply:
				printf("#CMP4503 ARP Reply received.#");
				/*Send quequed packages and update arp cache*/
				if (packet->ar_tip == interface->ip) {
					/*look for the request*/
					struct sr_arpreq* requestPointer = sr_arpcache_insert(
						&sr->cache, packet->ar_sha, ntohl(packet->ar_sip));
					if (requestPointer != NULL) {
						/*Send quequed packages*/
						printf("#CMP4503 Received ARP reply, sending all queued packets.\n");
						int waiting_count = 1;
						while (requestPointer->packets != NULL)
						{	
							struct sr_packet* curr = requestPointer->packets;
							printf("#CMP4503 Copy in the newly discovered Ethernet address of the frame");
							memcpy(((sr_ethernet_hdr_t*)curr->buf)->ether_dhost,
								packet->ar_sha, ETHER_ADDR_LEN);

							printf("#CMP4503 Sending %d . package waiting for this ip",waiting_count);
							sr_send_packet(sr, curr->buf, curr->len, curr->iface);

							requestPointer->packets = requestPointer->packets->next;
							waiting_count++;

							free(curr->buf);
							free(curr->iface);
							free(curr);
						}
						/*update ARP cache*/
						sr_arpreq_destroy(&sr->cache, requestPointer);
					}
					else
					{
						printf("#CMP4503 Received ARP reply, but found no request.\n");
					}
				}
				break;
		  }
		  break;

	  case ethertype_ip:
		  /*handle ip packet here*/
		  break;

	  default:
		  Debug("Dropping packet due to invalid Ethernet message type: 0x%X.\n", ethertype(packet));
		  return;
  }

  
  /*#CMP4503 OUR CODE ENDS HERE*/

}/* end sr_ForwardPacket */

