#include <vnet/int/int_def.h>
#include <vnet/udp/udp.h>

int_main_t int_main;

static inline u8 * init_int_info(u8 max_hop)
{
	u8 *result = NULL;
	int_header_t *inwt_inth;
	u8 header_length = 0;

	u8 *p_metadata_stack;

	header_length += sizeof(int_header_t);
	u8 length_metadata_stack = max_hop * 24;

	header_length += length_metadata_stack;  //Currently, length of int_metadata per hop is 24 byte

	vec_validate(result, header_length-1);

	inwt_inth = (int_header_t *) result;
	inwt_inth->type = 1;   //hop-by-hop type
	inwt_inth->shim_header_reserved = 0;
	inwt_inth->length = header_length;
	inwt_inth->next_protocol = 0;
	inwt_inth->flags = 0x1000;
	inwt_inth->metadata_length_of_per_hop = 0x18;  //24 byte
	inwt_inth->pointer_to_hops = 0x0c;  // =12
	inwt_inth->instruction_bitmap = 0;
	inwt_inth->metadata_header_reserved = 0;
	p_metadata_stack = inwt_inth->metadata_stack;
	for(u8 i=0; i<length_metadata_stack; ++i)
		clib_memset(p_metadata_stack + i, 0, sizeof(*p_metadata_stack));
	
	return result;
}

static inline void create_int_policy(int_policy_t * int_policy)
{
	u8 max_hop = 3;
	int_policy->int_info = init_int_info(max_hop);
}

int init_int_policy()
{
	int_main_t *im = &int_main;
	int_policy_t *int_policy = 0;

	pool_get(im->int_policies, int_policy);
	clib_memset(int_policy, 0, sizeof(*int_policy));
	create_int_policy(int_policy);
	return 0;
}

clib_error_t* int_init(vlib_main_t * vm)
{
	int_main_t *im = &int_main;
	
	udp_register_dst_port (vm, UDP_DST_PORT_int_gen,
		 int_header_generation_node.index, /* is_ip4 */ 1);
	
	int_template_header_t h;
	clib_memset (&h, 0, sizeof (h));
	vlib_packet_template_init (vm, &im->int_packet_template,
		    /* data */  &h,
		    sizeof (h),
		    /* alloc chunk size */ 8,
		    "int template");

	im->log_class = vlib_log_register_class ("int", 0);

	init_int_policy();

	return 0;
}

VLIB_INIT_FUNCTION (int_init);

