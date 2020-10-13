#ifndef _vnet_int_def_h
#define _vnet_int_def_h

#include <vnet/vnet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip.h>
#include <vlib/log.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
} int_header_gen_trace_t;

typedef struct
{
	u8 type;
	u8 shim_header_reserved;
	u8 length;
	u8 next_protocol;

	u16 flags;
	u8 metadata_length_of_per_hop;
	u8 pointer_to_hops;

	u16 instruction_bitmap;
	u16 metadata_header_reserved;

	u8 metadata_stack[0];
} __attribute__ ((packed)) int_header_t;

typedef struct
{
	u8* int_info;
} int_policy_t;

typedef struct
{
	ethernet_header_t l2_header;
	ip4_header_t l3_header;
} __attribute__ ((packed)) int_template_header_t;


typedef struct
{
	int_policy_t *int_policies;

	/** Template used to generate INT probe packets. */
	vlib_packet_template_t int_packet_template;
	
	/** log class */
	vlib_log_class_t log_class;
} int_main_t;

extern int_main_t int_main;

extern vlib_node_registration_t int_header_generation_node;

extern int_main_t int_main_v2;

extern vlib_node_registration_t int_header_generation_node_v2;

#endif

