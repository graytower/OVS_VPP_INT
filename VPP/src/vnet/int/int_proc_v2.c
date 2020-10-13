#include <vlib/vlib.h>
#include <vppinfra/vec_bootstrap.h>
#include <vppinfra/error.h>
#include <vnet/int/int_def.h>
#include <vnet/ethernet/ethernet.h>

extern vlib_node_registration_t int_header_generation_node_v2;

#define foreach_int_error \
_(NO_BUFFERS, "INT no buffers error")

typedef enum
{
#define _(sym,str) INT_ERROR_##sym,
  foreach_int_error
#undef _
    INT_PACKET_N_ERROR,
} int_error_t;

static char *int_error_strings[] = {
#define _(sym,string) string,
  foreach_int_error
#undef _
};

typedef enum
{
  INT_NEXT_LOOKUP,
  INT_NEXT_DROP,
  INT_N_NEXT,
} int_next_t;


void * get_int_packet_template_v2(vlib_main_t * vm,
				 vlib_packet_template_t * t, vlib_buffer_t *b0, u32 * bi_result)
{
  u32 bi;
  vlib_buffer_t *b;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return 0;

  *bi_result = bi;

  b = vlib_get_buffer (vm, bi);
  
  clib_memcpy_fast (vlib_buffer_get_current (b),
		    vlib_buffer_get_current (b0), vec_len (t->packet_data));
  b->current_length = b0->current_length;

  return b->data;
}


VLIB_NODE_FN(int_header_generation_node_v2) (vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_frame_t * from_frame)
{

	int_main_t *iim = &int_main_v2;

    u32 n_left_from, next_index, *from, *to_next;

	from = vlib_frame_vector_args (from_frame);
	n_left_from = from_frame->n_vectors;

	next_index = INT_NEXT_DROP;

	while(n_left_from > 0)
	{
		u32 n_left_to_next;
		vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

		while(n_left_from > 0 && n_left_to_next > 0)
		{
			u32 bi0;
			vlib_buffer_t *b0;

			int_policy_t *inwt_policy = 0;
			int_policy_t **vec_policies = 0;

			bi0 = from[0];
			from += 1;
			n_left_from -= 1;
			to_next[0] = bi0;
			to_next += 1;
			n_left_to_next -= 1;

			b0 = vlib_get_buffer(vm, bi0);
			vlib_buffer_advance(b0, -(word)(sizeof(ethernet_header_t)/*+sizeof(ip4_header_t)+sizeof(udp_header_t)*/));

			pool_foreach(inwt_policy, iim->int_policies,
						{vec_add1(vec_policies, inwt_policy); } );

			int i = 0;
			vec_foreach_index(i, vec_policies)
			{
				int_template_header_t *h;
				vlib_buffer_t *c0;
				u32 ci0;

				inwt_policy = vec_policies[i];

				h = get_int_packet_template_v2(vm,
								&iim->int_packet_template,
								b0,
								&ci0);
				if(PREDICT_FALSE(!h))
				{
					b0->error = node->errors[INT_ERROR_NO_BUFFERS];
					continue;
				}

				//ethernet_header_t *log_l2 = &(h->l2_header);
				// 			format_mac_address, log_l2->src_address);
				//ip4_header_t* log_l3 = &(h->l3_header);
				//vlib_log_warn(iim->log_class, "h ip4_length: %d", clib_host_to_net_u16(log_l3->length));
		
				c0 = vlib_get_buffer(vm, ci0);
				vnet_buffer(c0)->sw_if_index[VLIB_RX] = vnet_buffer(b0)->sw_if_index[VLIB_RX];

				ASSERT (c0->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=	vec_len (inwt_policy->int_info));

				int_template_header_t *template_h0 = 0;
				template_h0 = vlib_buffer_get_current(c0);
				
				int_header_t *int0 = 0;
				int0 = (int_header_t *) (template_h0 + 1);

				clib_memcpy_fast((u8 *)template_h0 - vec_len(inwt_policy->int_info),
					(u8 *)template_h0, sizeof(ethernet_header_t) + sizeof(ip4_header_t));
				clib_memcpy_fast((u8 *)int0 - vec_len(inwt_policy->int_info),
					inwt_policy->int_info, vec_len(inwt_policy->int_info));

				//copy data
				vlib_buffer_advance(b0, (word)(sizeof(ethernet_header_t)));
				ip4_header_t* ip = vlib_buffer_get_current(b0);
				u32 len = clib_host_to_net_u16(ip->length) - sizeof(ip4_header_t);
				vlib_buffer_advance(b0, (word)(sizeof(ip4_header_t)));
				u8 * pdata = vlib_buffer_get_current(b0);
				clib_memcpy_fast((u8 *)int0, pdata, len);
				vlib_buffer_advance(b0, -(word)(sizeof(ethernet_header_t)+sizeof(ip4_header_t)));
				
				template_h0 = ((void *) template_h0) - vec_len(inwt_policy->int_info);
				int0 = ((void *) int0) - vec_len(inwt_policy->int_info);

				u8 old_protocol = 0;
				u16 new_l0 = 0;
				ip4_header_t *ip0  = 0;
				u32 advance1 = 0;
				u32 advance2 = 0;

				ip0 = &(template_h0->l3_header);
				
				new_l0 = vec_len(inwt_policy->int_info);
				ip0->length += clib_host_to_net_u16(new_l0);
				
				old_protocol = ip0->protocol;
				ip0->protocol = 222; //
				ip0->checksum = ip4_header_checksum(ip0);

				int0->next_protocol = old_protocol;

				advance1 = vec_len(inwt_policy->int_info);
				advance2 = sizeof(ethernet_header_t);
				vlib_buffer_advance(c0, -(word)advance1);
				vlib_buffer_advance(c0, (word)advance2);
				
				vlib_buffer_copy_trace_flag(vm, b0, ci0);
				VLIB_BUFFER_TRACE_TRAJECTORY_INIT (c0);

				vlib_set_next_frame_buffer (vm, node,
				      INT_NEXT_LOOKUP, ci0);
			}

		}

		vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	}
	
	//vlib_log_warn(iim->log_class, "End int header generation v2 node");
	
	return from_frame->n_vectors;
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (int_header_generation_node_v2) = {
  .name = "int-header-generation-v2",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(int_error_strings),
  .error_strings = int_error_strings,
  
  .n_next_nodes = INT_N_NEXT,

  .next_nodes = {
    [INT_NEXT_LOOKUP] = "ip4-lookup",
    [INT_NEXT_DROP] = "error-drop",
  },
};



