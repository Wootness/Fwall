#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <linux/types.h>
#include <linux/string.h>
#include "firewall_main.h"
#include "firewall_manipulations.h"

// "Manipulation Instruction" list
// List of registered manipulations to apply to out-going packets
manipulation_inst_t* maniplutaions_list = NULL;

// "Awaiting connections" list
// List of partial instructions waiting for the userspace to retrieve it
manipulation_inst_t* new_awaiting_connection = NULL;


int add_manipulation_inst(__be32 client_ip, __be32 server_ip, __be16 client_port,  __be16 server_port, __be16 manipulation_port)
{
    manipulation_inst_t* node;

    node = (manipulation_inst_t *)kcalloc(1, sizeof(manipulation_inst_t), GFP_ATOMIC);
    if(!node) {
        return 0;
    }
    node->client_ip = client_ip;
    node->client_port = client_port;
    node->server_ip = server_ip;
    node->server_port = server_port;
    node->manipulation_port = manipulation_port;
    // Preppanding as new list's head
    node->next = maniplutaions_list;
    maniplutaions_list = node;
    return 1;
}


void remove_manipulation_inst(__be32 client_ip, __be32 server_ip, __be16 client_port,  __be16 server_port, __be16 manipulation_port)
{
    manipulation_inst_t* curr;
    manipulation_inst_t* last;

    curr = maniplutaions_list;
    if(curr == NULL)
        return;
    if(curr->client_ip == client_ip && curr->client_port == client_port &&
            curr->server_ip == server_ip && curr->server_port == server_port &&
            curr->manipulation_port == manipulation_port){
        // Special case - matching node is the list's head.
        maniplutaions_list = curr->next;
        kfree(curr);
        return;
    }
    last = curr;
    curr = curr->next;
    while(curr) {
        if(curr->client_ip == client_ip && curr->client_port == client_port &&
            curr->server_ip == server_ip && curr->server_port == server_port &&
            curr->manipulation_port == manipulation_port){
            // Remove matching node and stich nodes before and after
            last->next = curr->next;
            kfree(curr);
            return;
        }
        curr = curr->next;
    }
}


void reset_manipulations_list(void)
{
    manipulation_inst_t* curr;
    manipulation_inst_t* next;

    curr = maniplutaions_list;
    while(curr) {
        next = curr->next;
        kfree(curr);
        curr = next;
    }
    maniplutaions_list = NULL;
}


void register_awaiting_connection(__be32 client_ip, __be32 server_ip, __be16 client_port,  __be16 server_port)
{
    manipulation_inst_t *new_inst;
    new_inst = (manipulation_inst_t *)kcalloc(1, sizeof(manipulation_inst_t), GFP_ATOMIC);
    if(!new_inst) {
        return;
    }
    new_inst->client_ip = client_ip;
    new_inst->client_port = client_port;
    new_inst->server_ip = server_ip;
    new_inst->server_port = server_port;
     // Manipulation port is unkown at this stage, we need userspace to tell us
    new_inst->manipulation_port = NO_MANIPULATION_PORT;
    new_inst->next = NULL;
    // No list yet, setting as head
    if(new_awaiting_connection == NULL) {
        new_awaiting_connection = new_inst;
        return;
    }
    // Appending at list's end
    while(new_awaiting_connection->next != NULL)
    {
        new_awaiting_connection = new_awaiting_connection->next;
    }
    new_awaiting_connection->next = new_inst;
    return;

}


manipulation_inst_t* get_awaiting_connection(void)
{
    manipulation_inst_t *res;
    if(new_awaiting_connection == NULL)
        return NULL;
    res = new_awaiting_connection;
    new_awaiting_connection = res->next;
    return res;
}


void reset_awaiting_manipulations_list(void)
{
    manipulation_inst_t* curr;
    manipulation_inst_t* next;

    curr = new_awaiting_connection;
    while(curr) {
        next = curr->next;
        kfree(curr);
        curr = next;
    }
    new_awaiting_connection = NULL;
}


void fix_checksums(struct sk_buff *skb,struct iphdr *ip_header, struct tcphdr* tcp_header)
{
    int tcplen;

    tcplen = (skb->len - ((ip_header->ihl )<< 2));
    tcp_header->check=0;
    
    tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr,csum_partial((char*)tcp_header, tcplen,0));
    skb->ip_summed = CHECKSUM_NONE;
    ip_header->check = 0;
    
    ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);   
}


int manipulate_preroute(struct sk_buff *skb,struct iphdr *ip_header, struct tcphdr* tcp_header, conn_table_entry_t* matching_rule)
{
    if((tcp_header->source == HTTP_PORT || tcp_header->source == FTP_PORT) && tcp_header->dest == matching_rule->manipulation_port) {
        // This is traffic from the server towards the client with OUR FW's PORT
        // re-routing packet to us - changing IP
        ip_header->daddr = OUT_NET_FIREWALL_ADDR;
        fix_checksums(skb,ip_header,tcp_header);
        
        return MANIP_RESULTS_MANIPULATED;
    }

    if(tcp_header->dest == HTTP_PORT || tcp_header->dest == FTP_PORT) {
        // This is traffic from the client towards the HTTP/FTP server
        // re-routing packet to us - changing both IP and PORT
        ip_header->daddr = IN_NET_FIREWALL_ADDR;
        if(tcp_header->dest == HTTP_PORT)
            tcp_header->dest = HTTP_MANIPULATION_PORT;
        else
            tcp_header->dest = FTP_MANIPULATION_PORT;
        fix_checksums(skb,ip_header,tcp_header);
        return MANIP_RESULTS_MANIPULATED;
    }

    return MANIP_RESULTS_UNTOUCHED;
}


int manipulate_output(struct sk_buff *skb,struct iphdr *ip_header, struct tcphdr* tcp_header)
{
    manipulation_inst_t* curr;
    
    if(tcp_header->dest == HTTP_PORT || tcp_header->dest == FTP_PORT) {
        // This is traffic exiting the local machine towards the HTTP/FTP server
        // We are changing only the SOURCE IP to the client's IP
        curr = maniplutaions_list;
        while(curr) {
            if(tcp_header->source == curr->manipulation_port &&
                ip_header->daddr == curr->server_ip && tcp_header->dest == curr->server_port) {
                // Found the right rule
                ip_header->saddr = curr->client_ip;
                fix_checksums(skb,ip_header,tcp_header);
                return MANIP_RESULTS_MANIPULATED;
            }
            curr = curr->next;
        }
    }

    if(tcp_header->source == HTTP_MANIPULATION_PORT || tcp_header->source == FTP_MANIPULATION_PORT) {
        // This is traffic exiting the local machine towards the client
        // We are changing the SOURCE IP and SOURCE PORT to the server's IP,PORT
        curr = maniplutaions_list;
        while(curr) {
            if(ip_header->daddr == curr->client_ip && tcp_header->dest == curr->client_port) {
                // Found the right rule
                ip_header->saddr = curr->server_ip;
                tcp_header->source = curr->server_port;
                
                if(tcp_header->psh) {
                    /* Calculate pointers for begin and end of TCP packet data */
                    fix_checksums(skb,ip_header,tcp_header);
                }
                else
                    fix_checksums(skb,ip_header,tcp_header);
                
                return MANIP_RESULTS_MANIPULATED;
            }
            curr = curr->next;
        }
    }

    return MANIP_RESULTS_UNTOUCHED;
}