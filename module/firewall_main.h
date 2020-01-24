#ifndef _FW_MAIN_H
#define _FW_MAIN_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/list.h>

// IP address checks
#define IS_LOOPBACK_IP(addr) ((addr & 0x000000FF) == 0x0000007d)

// the protocols we will work with
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
} prot_t;


// various reasons to be registered in each log entry
typedef enum {
	REASON_FW_INACTIVE           = -1,
	REASON_NO_MATCHING_RULE      = -2,
	REASON_XMAS_PACKET           = -4,
	REASON_ILLEGAL_VALUE         = -6,
} reason_t;
	

// auxiliary strings
#define DEVICE_NAME_RULES			"rules"
#define DEVICE_NAME_LOG				"log"
#define DEVICE_NAME_DYN_TABLE		"dyn_table"
#define DEVICE_NAME_MANIP			"manipulations"
#define DEVICE_NAME_CONNS			"conns"
#define CLASS_NAME					"fw"
#define LOOPBACK_NET_DEVICE_NAME	"lo"
#define IN_NET_DEVICE_NAME			"eth1"
#define OUT_NET_DEVICE_NAME			"eth2"
#define IN_NET_FIREWALL_ADDR		0x0301000A
#define OUT_NET_FIREWALL_ADDR		0x0302000A
#define HTTP_PORT					0x5000 
#define FTP_PORT					0x1500 
#define SMTP_PORT					0x1900 
#define HTTP_MANIPULATION_PORT		0x2003 
#define FTP_MANIPULATION_PORT		0xD200 
#define SMTP_MANIPULATION_PORT		0xFA00 
#define NO_MANIPULATION_PORT		0
#define MANIPULATION_CMD_INST		0
#define MANIPULATION_CMD_FTP_DATA	1

// auxiliary values
#define IP_VERSION		(4)
#define PORT_ANY		(0)
#define PORT_ABOVE_1023	(1023)
#define ABOVE_1023_INDICATOR	(1024) // Using this number to indicate ALL ports above 1023
#define ABOVE_1023_INDICATOR_NETORD	(0x0004) // Above number, but in network order
#define MAX_RULES		(50)

// device minor numbers
typedef enum {
	MINOR_RULES			= 0,
	MINOR_LOG			= 1,
	MINOR_LOG_RESET		= 2,
	MINOR_MANIP			= 3,
	MINOR_CONNS			= 4,
} minor_t;

typedef enum {
	ACK_NO 		= 0x01,
	ACK_YES 	= 0x02,
	ACK_ANY 	= ACK_NO | ACK_YES,
} ack_t;

typedef enum {
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

typedef enum {
	TCP_STATE_INVALID	 		= 0,
	TCP_STATE_SYN_SENT 			= 1,
	TCP_STATE_SYN_RECV 			= 2, // SYN-ACK Sent
	TCP_STATE_ESTABLISHED 		= 3,
	TCP_STATE_FIN_SENT 			= 4,
	TCP_STATE_FIN_RECV 			= 5,
	TCP_STATE_CLOSED 			= 6,
	TCP_STATE_EXPECTING_INIT	= 7, // Not an offical state, used internally when waiting for 'secondary' connection
} tcp_state_t;


#endif // _FW_MAIN_H
