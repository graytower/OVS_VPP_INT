#include <vnet/int/int_def.h>
#include <vnet/udp/udp.h>

int_main_t int_main_v2;

static inline u8 * init_int_info_v2()
{
	u8 *result = NULL;
	int_header_t *inwt_inth;
	u8 header_length = 0;

	u8 *p_metadata_stack;

	header_length += sizeof(int_header_t);
	u8 length_metadata_stack = 24;

	header_length += length_metadata_stack;

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

static inline void create_int_policy_v2(int_policy_t * int_policy)
{
	int_policy->int_info = init_int_info_v2();
}

int init_int_policy_v2()
{
	int_main_t *im = &int_main_v2;
	int_policy_t *int_policy = 0;

	pool_get(im->int_policies, int_policy);
	clib_memset(int_policy, 0, sizeof(*int_policy));
	create_int_policy_v2(int_policy);
	return 0;
}

clib_error_t* int_init_v2(vlib_main_t * vm)
{
	int_main_t *im = &int_main_v2;
	
	int_template_header_t h;
	clib_memset (&h, 0, sizeof (h));
	vlib_packet_template_init (vm, &im->int_packet_template,
		    /* data */  &h,
		    sizeof (h),
		    /* alloc chunk size */ 8,
		    "int template v2");

	im->log_class = vlib_log_register_class ("int_v2", 0);

	init_int_policy_v2();

	return 0;
}

VLIB_INIT_FUNCTION (int_init_v2);


