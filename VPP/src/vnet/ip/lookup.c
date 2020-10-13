/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * ip/ip_lookup.c: ip4/6 adjacency and lookup table management
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vnet/ip/ip.h>
#include <vnet/adj/adj.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/mpls/mpls.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/classify_dpo.h>
#include <vnet/dpo/punt_dpo.h>
#include <vnet/dpo/receive_dpo.h>
#include <vnet/dpo/ip_null_dpo.h>
#include <vnet/dpo/l3_proxy_dpo.h>

/**
 * @file
 * @brief IPv4 and IPv6 adjacency and lookup table management.
 *
 */

clib_error_t *
ip_interface_address_add_del (ip_lookup_main_t * lm,
			      u32 sw_if_index,
			      void *addr_fib,
			      u32 address_length,
			      u32 is_del, u32 * result_if_address_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip_interface_address_t *a, *prev, *next;
  uword *p = mhash_get (&lm->address_to_if_address_index, addr_fib);

  vec_validate_init_empty (lm->if_address_pool_index_by_sw_if_index,
			   sw_if_index, ~0);
  a = p ? pool_elt_at_index (lm->if_address_pool, p[0]) : 0;

  /* Verify given length. */
  if ((a && (address_length != a->address_length)) ||
      (address_length == 0) ||
      (lm->is_ip6 && address_length > 128) ||
      (!lm->is_ip6 && address_length > 32))
    {
      vnm->api_errno = VNET_API_ERROR_ADDRESS_LENGTH_MISMATCH;
      return clib_error_create
	("%U wrong length (expected %d) for interface %U",
	 lm->format_address_and_length, addr_fib,
	 address_length, a ? a->address_length : -1,
	 format_vnet_sw_if_index_name, vnm, sw_if_index);
    }

  if (is_del)
    {
      if (!a)
	{
	  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
	  vnm->api_errno = VNET_API_ERROR_ADDRESS_NOT_FOUND_FOR_INTERFACE;
	  return clib_error_create ("%U not found for interface %U",
				    lm->format_address_and_length,
				    addr_fib, address_length,
				    format_vnet_sw_interface_name, vnm, si);
	}

      if (a->prev_this_sw_interface != ~0)
	{
	  prev =
	    pool_elt_at_index (lm->if_address_pool,
			       a->prev_this_sw_interface);
	  prev->next_this_sw_interface = a->next_this_sw_interface;
	}
      if (a->next_this_sw_interface != ~0)
	{
	  next =
	    pool_elt_at_index (lm->if_address_pool,
			       a->next_this_sw_interface);
	  next->prev_this_sw_interface = a->prev_this_sw_interface;

	  if (a->prev_this_sw_interface == ~0)
	    lm->if_address_pool_index_by_sw_if_index[sw_if_index] =
	      a->next_this_sw_interface;
	}

      if ((a->next_this_sw_interface == ~0)
	  && (a->prev_this_sw_interface == ~0))
	lm->if_address_pool_index_by_sw_if_index[sw_if_index] = ~0;

      mhash_unset (&lm->address_to_if_address_index, addr_fib,
		   /* old_value */ 0);
      pool_put (lm->if_address_pool, a);

      if (result_if_address_index)
	*result_if_address_index = ~0;
    }

  else if (!a)
    {
      u32 pi;			/* previous index */
      u32 ai;
      u32 hi;			/* head index */

      pool_get (lm->if_address_pool, a);
      clib_memset (a, ~0, sizeof (a[0]));
      ai = a - lm->if_address_pool;

      hi = pi = lm->if_address_pool_index_by_sw_if_index[sw_if_index];
      prev = 0;
      while (pi != (u32) ~ 0)
	{
	  prev = pool_elt_at_index (lm->if_address_pool, pi);
	  pi = prev->next_this_sw_interface;
	}
      pi = prev ? prev - lm->if_address_pool : (u32) ~ 0;

      a->address_key = mhash_set (&lm->address_to_if_address_index,
				  addr_fib, ai, /* old_value */ 0);
      a->address_length = address_length;
      a->sw_if_index = sw_if_index;
      a->flags = 0;
      a->prev_this_sw_interface = pi;
      a->next_this_sw_interface = ~0;
      if (prev)
	prev->next_this_sw_interface = ai;

      lm->if_address_pool_index_by_sw_if_index[sw_if_index] =
	(hi != ~0) ? hi : ai;
      if (result_if_address_index)
	*result_if_address_index = ai;
    }
  else
    {
      if (sw_if_index != a->sw_if_index)
	{
	  if (result_if_address_index)
	    *result_if_address_index = ~0;
	  vnm->api_errno = VNET_API_ERROR_DUPLICATE_IF_ADDRESS;
	  return clib_error_create
	    ("Prefix %U already found on interface %U",
	     lm->format_address_and_length, addr_fib, address_length,
	     format_vnet_sw_if_index_name, vnm, a->sw_if_index);
	}

      if (result_if_address_index)
	*result_if_address_index = a - lm->if_address_pool;
    }

  return /* no error */ 0;
}

static clib_error_t *
ip_sw_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
  vec_validate_init_empty (ip4_main.
			   lookup_main.if_address_pool_index_by_sw_if_index,
			   sw_if_index, ~0);
  vec_validate_init_empty (ip6_main.
			   lookup_main.if_address_pool_index_by_sw_if_index,
			   sw_if_index, ~0);

  return (NULL);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (ip_sw_interface_add_del);

void
ip_lookup_init (ip_lookup_main_t * lm, u32 is_ip6)
{
  if (!lm->fib_result_n_bytes)
    lm->fib_result_n_bytes = sizeof (uword);

  lm->is_ip6 = is_ip6;
  mhash_init (&lm->prefix_to_if_prefix_index, sizeof (uword),
	      sizeof (ip_interface_prefix_key_t));
  if (is_ip6)
    {
      lm->format_address_and_length = format_ip6_address_and_length;
      mhash_init (&lm->address_to_if_address_index, sizeof (uword),
		  sizeof (ip6_address_fib_t));
    }
  else
    {
      lm->format_address_and_length = format_ip4_address_and_length;
      mhash_init (&lm->address_to_if_address_index, sizeof (uword),
		  sizeof (ip4_address_fib_t));
    }

  {
    int i;

    /* Setup all IP protocols to be punted and builtin-unknown. */
    for (i = 0; i < 256; i++)
      {
	lm->local_next_by_ip_protocol[i] = IP_LOCAL_NEXT_PUNT;
	lm->builtin_protocol_by_ip_protocol[i] = IP_BUILTIN_PROTOCOL_UNKNOWN;
      }

    lm->local_next_by_ip_protocol[IP_PROTOCOL_UDP] = IP_LOCAL_NEXT_UDP_LOOKUP;
    lm->local_next_by_ip_protocol[is_ip6 ? IP_PROTOCOL_ICMP6 :
				  IP_PROTOCOL_ICMP] = IP_LOCAL_NEXT_ICMP;
    lm->builtin_protocol_by_ip_protocol[IP_PROTOCOL_UDP] =
      IP_BUILTIN_PROTOCOL_UDP;
    lm->builtin_protocol_by_ip_protocol[is_ip6 ? IP_PROTOCOL_ICMP6 :
					IP_PROTOCOL_ICMP] =
      IP_BUILTIN_PROTOCOL_ICMP;
  }
}

u8 *
format_ip_flow_hash_config (u8 * s, va_list * args)
{
  flow_hash_config_t flow_hash_config = va_arg (*args, u32);

#define _(n,v) if (flow_hash_config & v) s = format (s, "%s ", #n);
  foreach_flow_hash_bit;
#undef _

  return s;
}

u8 *
format_ip_adjacency_packet_data (u8 * s, va_list * args)
{
  u8 *packet_data = va_arg (*args, u8 *);
  u32 n_packet_data_bytes = va_arg (*args, u32);

  s = format (s, "%U", format_hex_bytes, packet_data, n_packet_data_bytes);

  return s;
}

static uword
unformat_dpo (unformat_input_t * input, va_list * args)
{
  dpo_id_t *dpo = va_arg (*args, dpo_id_t *);
  fib_protocol_t fp = va_arg (*args, int);
  dpo_proto_t proto;

  proto = fib_proto_to_dpo (fp);

  if (unformat (input, "drop"))
    dpo_copy (dpo, drop_dpo_get (proto));
  else if (unformat (input, "punt"))
    dpo_copy (dpo, punt_dpo_get (proto));
  else if (unformat (input, "local"))
    receive_dpo_add_or_lock (proto, ~0, NULL, dpo);
  else if (unformat (input, "null-send-unreach"))
    ip_null_dpo_add_and_lock (proto, IP_NULL_ACTION_SEND_ICMP_UNREACH, dpo);
  else if (unformat (input, "null-send-prohibit"))
    ip_null_dpo_add_and_lock (proto, IP_NULL_ACTION_SEND_ICMP_PROHIBIT, dpo);
  else if (unformat (input, "null"))
    ip_null_dpo_add_and_lock (proto, IP_NULL_ACTION_NONE, dpo);
  else if (unformat (input, "classify"))
    {
      u32 classify_table_index;

      if (!unformat (input, "%d", &classify_table_index))
	{
	  clib_warning ("classify adj must specify table index");
	  return 0;
	}

      dpo_set (dpo, DPO_CLASSIFY, proto,
	       classify_dpo_create (proto, classify_table_index));
    }
  else
    return 0;

  return 1;
}

const ip46_address_t zero_addr = {
  .as_u64 = {
	     0, 0},
};

static clib_error_t *
vnet_ip_route_cmd (vlib_main_t * vm,
		   unformat_input_t * main_input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 table_id, is_del, fib_index, payload_proto;
  dpo_id_t dpo = DPO_INVALID, *dpos = NULL;
  fib_route_path_t *rpaths = NULL, rpath;
  fib_prefix_t *prefixs = NULL, pfx;
  clib_error_t *error = NULL;
  f64 count;
  int i;

  is_del = 0;
  table_id = 0;
  count = 1;
  clib_memset (&pfx, 0, sizeof (pfx));

  /* Get a line of input. */
  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      clib_memset (&rpath, 0, sizeof (rpath));

      if (unformat (line_input, "table %d", &table_id))
	;
      else if (unformat (line_input, "count %f", &count))
	;

      else if (unformat (line_input, "%U/%d",
			 unformat_ip4_address, &pfx.fp_addr.ip4, &pfx.fp_len))
	{
	  payload_proto = pfx.fp_proto = FIB_PROTOCOL_IP4;
	  vec_add1 (prefixs, pfx);
	}
      else if (unformat (line_input, "%U/%d",
			 unformat_ip6_address, &pfx.fp_addr.ip6, &pfx.fp_len))
	{
	  payload_proto = pfx.fp_proto = FIB_PROTOCOL_IP6;
	  vec_add1 (prefixs, pfx);
	}
      else if (unformat (line_input, "via %U",
			 unformat_fib_route_path, &rpath, &payload_proto))
	{
	  vec_add1 (rpaths, rpath);
	}
      else if (vec_len (prefixs) > 0 &&
	       unformat (line_input, "via %U",
			 unformat_dpo, &dpo, prefixs[0].fp_proto))
	{
	  vec_add1 (dpos, dpo);
	}
      else if (unformat (line_input, "del"))
	is_del = 1;
      else if (unformat (line_input, "add"))
	is_del = 0;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (vec_len (prefixs) == 0)
    {
      error =
	clib_error_return (0, "expected ip4/ip6 destination address/length.");
      goto done;
    }

  if (!is_del && vec_len (rpaths) + vec_len (dpos) == 0)
    {
      error = clib_error_return (0, "expected paths.");
      goto done;
    }

  if (~0 == table_id)
    {
      /*
       * if no table_id is passed we will manipulate the default
       */
      fib_index = 0;
    }
  else
    {
      fib_index = fib_table_find (prefixs[0].fp_proto, table_id);

      if (~0 == fib_index)
	{
	  error = clib_error_return (0, "Nonexistent table id %d", table_id);
	  goto done;
	}
    }

  for (i = 0; i < vec_len (prefixs); i++)
    {
      if (is_del && 0 == vec_len (rpaths))
	{
	  fib_table_entry_delete (fib_index, &prefixs[i], FIB_SOURCE_CLI);
	}
      else if (!is_del && 1 == vec_len (dpos))
	{
	  fib_table_entry_special_dpo_add (fib_index,
					   &prefixs[i],
					   FIB_SOURCE_CLI,
					   FIB_ENTRY_FLAG_EXCLUSIVE,
					   &dpos[0]);
	  dpo_reset (&dpos[0]);
	}
      else if (vec_len (dpos) > 0)
	{
	  error =
	    clib_error_return (0,
			       "Load-balancing over multiple special adjacencies is unsupported");
	  goto done;
	}
      else if (0 < vec_len (rpaths))
	{
	  u32 k, n, incr;
	  ip46_address_t dst = prefixs[i].fp_addr;
	  f64 t[2];
	  n = count;
	  t[0] = vlib_time_now (vm);
	  incr = 1 << ((FIB_PROTOCOL_IP4 == prefixs[0].fp_proto ? 32 : 128) -
		       prefixs[i].fp_len);

	  for (k = 0; k < n; k++)
	    {
	      fib_prefix_t rpfx = {
		.fp_len = prefixs[i].fp_len,
		.fp_proto = prefixs[i].fp_proto,
		.fp_addr = dst,
	      };

	      if (is_del)
		fib_table_entry_path_remove2 (fib_index,
					      &rpfx, FIB_SOURCE_CLI, rpaths);
	      else
		fib_table_entry_path_add2 (fib_index,
					   &rpfx,
					   FIB_SOURCE_CLI,
					   FIB_ENTRY_FLAG_NONE, rpaths);

	      if (FIB_PROTOCOL_IP4 == prefixs[0].fp_proto)
		{
		  dst.ip4.as_u32 =
		    clib_host_to_net_u32 (incr +
					  clib_net_to_host_u32 (dst.
								ip4.as_u32));
		}
	      else
		{
		  int bucket = (incr < 64 ? 0 : 1);
		  dst.ip6.as_u64[bucket] =
		    clib_host_to_net_u64 (incr +
					  clib_net_to_host_u64 (dst.ip6.as_u64
								[bucket]));
		}
	    }

	  t[1] = vlib_time_now (vm);
	  if (count > 1)
	    vlib_cli_output (vm, "%.6e routes/sec", count / (t[1] - t[0]));
	}
      else
	{
	  error = clib_error_return (0, "Don't understand what you want...");
	  goto done;
	}
    }

done:
  vec_free (dpos);
  vec_free (prefixs);
  vec_free (rpaths);
  unformat_free (line_input);
  return error;
}

clib_error_t *
vnet_ip_table_cmd (vlib_main_t * vm,
		   unformat_input_t * main_input,
		   vlib_cli_command_t * cmd, fib_protocol_t fproto)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u32 table_id, is_add;
  u8 *name = NULL;

  is_add = 1;
  table_id = ~0;

  /* Get a line of input. */
  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%d", &table_id))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "name %s", &name))
	;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (~0 == table_id)
    {
      error = clib_error_return (0, "No table id");
      goto done;
    }
  else if (0 == table_id)
    {
      error = clib_error_return (0, "Can't change the default table");
      goto done;
    }
  else
    {
      if (is_add)
	{
	  ip_table_create (fproto, table_id, 0, name);
	}
      else
	{
	  ip_table_delete (fproto, table_id, 0);
	}
    }

done:
  unformat_free (line_input);
  return error;
}

clib_error_t *
vnet_ip4_table_cmd (vlib_main_t * vm,
		    unformat_input_t * main_input, vlib_cli_command_t * cmd)
{
  return (vnet_ip_table_cmd (vm, main_input, cmd, FIB_PROTOCOL_IP4));
}

clib_error_t *
vnet_ip6_table_cmd (vlib_main_t * vm,
		    unformat_input_t * main_input, vlib_cli_command_t * cmd)
{
  return (vnet_ip_table_cmd (vm, main_input, cmd, FIB_PROTOCOL_IP6));
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_ip_command, static) = {
  .path = "ip",
  .short_help = "Internet protocol (IP) commands",
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_ip6_command, static) = {
  .path = "ip6",
  .short_help = "Internet protocol version 6 (IPv6) commands",
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_show_ip_command, static) = {
  .path = "show ip",
  .short_help = "Internet protocol (IP) show commands",
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_show_ip6_command, static) = {
  .path = "show ip6",
  .short_help = "Internet protocol version 6 (IPv6) show commands",
};
/* *INDENT-ON* */

/*?
 * This command is used to add or delete IPv4 or IPv6 routes. All
 * IP Addresses ('<em><dst-ip-addr>/<width></em>',
 * '<em><next-hop-ip-addr></em>' and '<em><adj-hop-ip-addr></em>')
 * can be IPv4 or IPv6, but all must be of the same form in a single
 * command. To display the current set of routes, use the commands
 * '<em>show ip fib</em>' and '<em>show ip6 fib</em>'.
 *
 * @cliexpar
 * Example of how to add a straight forward static route:
 * @cliexcmd{ip route add 6.0.1.2/32 via 6.0.0.1 GigabitEthernet2/0/0}
 * Example of how to delete a straight forward static route:
 * @cliexcmd{ip route del 6.0.1.2/32 via 6.0.0.1 GigabitEthernet2/0/0}
 * Mainly for route add/del performance testing, one can add or delete
 * multiple routes by adding 'count N' to the previous item:
 * @cliexcmd{ip route add count 10 7.0.0.0/24 via 6.0.0.1 GigabitEthernet2/0/0}
 * Add multiple routes for the same destination to create equal-cost multipath:
 * @cliexcmd{ip route add 7.0.0.1/32 via 6.0.0.1 GigabitEthernet2/0/0}
 * @cliexcmd{ip route add 7.0.0.1/32 via 6.0.0.2 GigabitEthernet2/0/0}
 * For unequal-cost multipath, specify the desired weights. This
 * combination of weights results in 3/4 of the traffic following the
 * second path, 1/4 following the first path:
 * @cliexcmd{ip route add 7.0.0.1/32 via 6.0.0.1 GigabitEthernet2/0/0 weight 1}
 * @cliexcmd{ip route add 7.0.0.1/32 via 6.0.0.2 GigabitEthernet2/0/0 weight 3}
 * To add a route to a particular FIB table (VRF), use:
 * @cliexcmd{ip route add 172.16.24.0/24 table 7 via GigabitEthernet2/0/0}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip_route_command, static) = {
  .path = "ip route",
  .short_help = "ip route [add|del] [count <n>] <dst-ip-addr>/<width> [table <table-id>] via [next-hop-address] [next-hop-interface] [next-hop-table <value>] [weight <value>] [preference <value>] [udp-encap-id <value>] [ip4-lookup-in-table <value>] [ip6-lookup-in-table <value>] [mpls-lookup-in-table <value>] [resolve-via-host] [resolve-via-connected] [rx-ip4 <interface>] [out-labels <value value value>]",
  .function = vnet_ip_route_cmd,
  .is_mp_safe = 1,
};

/* *INDENT-ON* */
/*?
 * This command is used to add or delete IPv4  Tables. All
 * Tables must be explicitly added before that can be used. Creating a
 * table will add both unicast and multicast FIBs
 *
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip4_table_command, static) = {
  .path = "ip table",
  .short_help = "ip table [add|del] <table-id>",
  .function = vnet_ip4_table_cmd,
};
/* *INDENT-ON* */

/* *INDENT-ON* */
/*?
 * This command is used to add or delete IPv4  Tables. All
 * Tables must be explicitly added before that can be used. Creating a
 * table will add both unicast and multicast FIBs
 *
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_table_command, static) = {
  .path = "ip6 table",
  .short_help = "ip6 table [add|del] <table-id>",
  .function = vnet_ip6_table_cmd,
};

static clib_error_t *
ip_table_bind_cmd (vlib_main_t * vm,
                   unformat_input_t * input,
                   vlib_cli_command_t * cmd,
                   fib_protocol_t fproto)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index, table_id;
  int rv;

  sw_if_index = ~0;

  if (!unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (unformat (input, "%d", &table_id))
    ;
  else
    {
      error = clib_error_return (0, "expected table id `%U'",
				 format_unformat_error, input);
      goto done;
    }

  rv = ip_table_bind (fproto, sw_if_index, table_id, 0);

  if (VNET_API_ERROR_ADDRESS_FOUND_FOR_INTERFACE == rv)
    {
      error = clib_error_return (0, "IP addresses are still present on %U",
                                 format_vnet_sw_if_index_name,
                                 vnet_get_main(),
                                 sw_if_index);
    }
  else if (VNET_API_ERROR_NO_SUCH_FIB == rv)
    {
      error = clib_error_return (0, "no such table %d", table_id);
    }
  else if (0 != rv)
    {
      error = clib_error_return (0, "unknown error");
    }

 done:
  return error;
}

static clib_error_t *
ip4_table_bind_cmd (vlib_main_t * vm,
                    unformat_input_t * input,
                    vlib_cli_command_t * cmd)
{
  return (ip_table_bind_cmd (vm , input, cmd, FIB_PROTOCOL_IP4));
}

static clib_error_t *
ip6_table_bind_cmd (vlib_main_t * vm,
                    unformat_input_t * input,
                    vlib_cli_command_t * cmd)
{
  return (ip_table_bind_cmd (vm , input, cmd, FIB_PROTOCOL_IP6));
}

/*?
 * Place the indicated interface into the supplied IPv4 FIB table (also known
 * as a VRF). The FIB table must be created using "ip table add" already. To
 * display the current IPv4 FIB table, use the command '<em>show ip fib</em>'.
 * FIB table will only be displayed if a route has been added to the table, or
 * an IP Address is assigned to an interface in the table (which adds a route
 * automatically).
 *
 * @note IP addresses added after setting the interface IP table are added to
 * the indicated FIB table. If an IP address is added prior to changing the
 * table then this is an error. The control plane must remove these addresses
 * first and then change the table. VPP will not automatically move the
 * addresses from the old to the new table as it does not know the validity
 * of such a change.
 *
 * @cliexpar
 * Example of how to add an interface to an IPv4 FIB table (where 2 is the table-id):
 * @cliexcmd{set interface ip table GigabitEthernet2/0/0 2}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_ip_table_command, static) =
{
  .path = "set interface ip table",
  .function = ip4_table_bind_cmd,
  .short_help = "set interface ip table <interface> <table-id>",
};
/* *INDENT-ON* */

/*?
 * Place the indicated interface into the supplied IPv6 FIB table (also known
 * as a VRF). The FIB table must be created using "ip6 table add" already. To
 * display the current IPv6 FIB table, use the command '<em>show ip6 fib</em>'.
 * FIB table will only be displayed if a route has been added to the table, or
 * an IP Address is assigned to an interface in the table (which adds a route
 * automatically).
 *
 * @note IP addresses added after setting the interface IP table are added to
 * the indicated FIB table. If an IP address is added prior to changing the
 * table then this is an error. The control plane must remove these addresses
 * first and then change the table. VPP will not automatically move the
 * addresses from the old to the new table as it does not know the validity
 * of such a change.
 *
 * @cliexpar
 * Example of how to add an interface to an IPv6 FIB table (where 2 is the table-id):
 * @cliexcmd{set interface ip6 table GigabitEthernet2/0/0 2}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_ip6_table_command, static) =
{
  .path = "set interface ip6 table",
  .function = ip6_table_bind_cmd,
  .short_help = "set interface ip6 table <interface> <table-id>"
};
/* *INDENT-ON* */

clib_error_t *
vnet_ip_mroute_cmd (vlib_main_t * vm,
		    unformat_input_t * main_input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  fib_route_path_t rpath, *rpaths = NULL;
  clib_error_t *error = NULL;
  u32 table_id, is_del, payload_proto;
  mfib_prefix_t pfx;
  u32 fib_index;
  mfib_entry_flags_t eflags = 0;
  u32 gcount, scount, ss, gg, incr;
  f64 timet[2];
  u32 rpf_id = MFIB_RPF_ID_NONE;

  gcount = scount = 1;
  is_del = 0;
  table_id = 0;
  clib_memset (&pfx, 0, sizeof (pfx));
  clib_memset (&rpath, 0, sizeof (rpath));
  rpath.frp_sw_if_index = ~0;

  /* Get a line of input. */
  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "table %d", &table_id))
	;
      else if (unformat (line_input, "del"))
	is_del = 1;
      else if (unformat (line_input, "add"))
	is_del = 0;
      else if (unformat (line_input, "rpf-id %d", &rpf_id))
	;
      else if (unformat (line_input, "scount %d", &scount))
	;
      else if (unformat (line_input, "gcount %d", &gcount))
	;
      else if (unformat (line_input, "%U %U",
			 unformat_ip4_address,
			 &pfx.fp_src_addr.ip4,
			 unformat_ip4_address, &pfx.fp_grp_addr.ip4))
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP4;
	  pfx.fp_len = 64;
	}
      else if (unformat (line_input, "%U %U",
			 unformat_ip6_address,
			 &pfx.fp_src_addr.ip6,
			 unformat_ip6_address, &pfx.fp_grp_addr.ip6))
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP6;
	  pfx.fp_len = 256;
	}
      else if (unformat (line_input, "%U/%d",
			 unformat_ip4_address,
			 &pfx.fp_grp_addr.ip4, &pfx.fp_len))
	{
	  clib_memset (&pfx.fp_src_addr.ip4, 0, sizeof (pfx.fp_src_addr.ip4));
	  pfx.fp_proto = FIB_PROTOCOL_IP4;
	}
      else if (unformat (line_input, "%U/%d",
			 unformat_ip6_address,
			 &pfx.fp_grp_addr.ip6, &pfx.fp_len))
	{
	  clib_memset (&pfx.fp_src_addr.ip6, 0, sizeof (pfx.fp_src_addr.ip6));
	  pfx.fp_proto = FIB_PROTOCOL_IP6;
	}
      else if (unformat (line_input, "%U",
			 unformat_ip4_address, &pfx.fp_grp_addr.ip4))
	{
	  clib_memset (&pfx.fp_src_addr.ip4, 0, sizeof (pfx.fp_src_addr.ip4));
	  pfx.fp_proto = FIB_PROTOCOL_IP4;
	  pfx.fp_len = 32;
	}
      else if (unformat (line_input, "%U",
			 unformat_ip6_address, &pfx.fp_grp_addr.ip6))
	{
	  clib_memset (&pfx.fp_src_addr.ip6, 0, sizeof (pfx.fp_src_addr.ip6));
	  pfx.fp_proto = FIB_PROTOCOL_IP6;
	  pfx.fp_len = 128;
	}
      else if (unformat (line_input, "via local Forward"))
	{
	  clib_memset (&rpath.frp_addr, 0, sizeof (rpath.frp_addr));
	  rpath.frp_sw_if_index = ~0;
	  rpath.frp_weight = 1;
	  rpath.frp_flags |= FIB_ROUTE_PATH_LOCAL;
	  /*
	   * set the path proto appropriately for the prefix
	   */
	  rpath.frp_proto = fib_proto_to_dpo (pfx.fp_proto);
	  rpath.frp_mitf_flags = MFIB_ITF_FLAG_FORWARD;

	  vec_add1 (rpaths, rpath);
	}
      else if (unformat (line_input, "via %U",
			 unformat_fib_route_path, &rpath, &payload_proto))
	{
	  vec_add1 (rpaths, rpath);
	}
      else if (unformat (line_input, "%U",
			 unformat_mfib_entry_flags, &eflags))
	;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (~0 == table_id)
    {
      /*
       * if no table_id is passed we will manipulate the default
       */
      fib_index = 0;
    }
  else
    {
      fib_index = mfib_table_find (pfx.fp_proto, table_id);

      if (~0 == fib_index)
	{
	  error = clib_error_return (0, "Nonexistent table id %d", table_id);
	  goto done;
	}
    }

  timet[0] = vlib_time_now (vm);

  if (FIB_PROTOCOL_IP4 == pfx.fp_proto)
    {
      incr = 1 << (32 - (pfx.fp_len % 32));
    }
  else
    {
      incr = 1 << (128 - (pfx.fp_len % 128));
    }

  for (ss = 0; ss < scount; ss++)
    {
      for (gg = 0; gg < gcount; gg++)
	{
	  if (is_del && 0 == vec_len (rpaths))
	    {
	      /* no path provided => route delete */
	      mfib_table_entry_delete (fib_index, &pfx, MFIB_SOURCE_CLI);
	    }
	  else if (eflags || (MFIB_RPF_ID_NONE != rpf_id))
	    {
	      mfib_table_entry_update (fib_index, &pfx, MFIB_SOURCE_CLI,
				       rpf_id, eflags);
	    }
	  else
	    {
	      if (is_del)
		mfib_table_entry_path_remove (fib_index,
					      &pfx, MFIB_SOURCE_CLI, rpaths);
	      else
		mfib_table_entry_path_update (fib_index,
					      &pfx, MFIB_SOURCE_CLI, rpaths);
	    }

	  if (FIB_PROTOCOL_IP4 == pfx.fp_proto)
	    {
	      pfx.fp_grp_addr.ip4.as_u32 =
		clib_host_to_net_u32 (incr +
				      clib_net_to_host_u32 (pfx.
							    fp_grp_addr.ip4.
							    as_u32));
	    }
	  else
	    {
	      int bucket = (incr < 64 ? 0 : 1);
	      pfx.fp_grp_addr.ip6.as_u64[bucket] =
		clib_host_to_net_u64 (incr +
				      clib_net_to_host_u64 (pfx.
							    fp_grp_addr.ip6.as_u64
							    [bucket]));

	    }
	}
      if (FIB_PROTOCOL_IP4 == pfx.fp_proto)
	{
	  pfx.fp_src_addr.ip4.as_u32 =
	    clib_host_to_net_u32 (1 +
				  clib_net_to_host_u32 (pfx.fp_src_addr.
							ip4.as_u32));
	}
      else
	{
	  pfx.fp_src_addr.ip6.as_u64[1] =
	    clib_host_to_net_u64 (1 +
				  clib_net_to_host_u64 (pfx.fp_src_addr.
							ip6.as_u64[1]));
	}
    }

  timet[1] = vlib_time_now (vm);

  if (scount > 1 || gcount > 1)
    vlib_cli_output (vm, "%.6e routes/sec",
		     (scount * gcount) / (timet[1] - timet[0]));

done:
  vec_free (rpaths);
  unformat_free (line_input);

  return error;
}

/*?
 * This command is used to add or delete IPv4 or IPv6  multicast routes. All
 * IP Addresses ('<em><dst-ip-addr>/<width></em>',
 * '<em><next-hop-ip-addr></em>' and '<em><adj-hop-ip-addr></em>')
 * can be IPv4 or IPv6, but all must be of the same form in a single
 * command. To display the current set of routes, use the commands
 * '<em>show ip mfib</em>' and '<em>show ip6 mfib</em>'.
 * The full set of support flags for interfaces and route is shown via;
 * '<em>show mfib route flags</em>' and '<em>show mfib itf flags</em>'
 * respectively.
 * @cliexpar
 * Example of how to add a forwarding interface to a route (and create the
 * route if it does not exist)
 * @cliexcmd{ip mroute add 232.1.1.1 via GigabitEthernet2/0/0 Forward}
 * Example of how to add an accepting interface to a route (and create the
 * route if it does not exist)
 * @cliexcmd{ip mroute add 232.1.1.1 via GigabitEthernet2/0/1 Accept}
 * Example of changing the route's flags to send signals via the API
 * @cliexcmd{ip mroute add 232.1.1.1 Signal}

 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip_mroute_command, static) =
{
  .path = "ip mroute",
  .short_help = "ip mroute [add|del] <dst-ip-addr>/<width> [table <table-id>] [rpf-id <ID>] [via <next-hop-ip-addr> [<interface>],",
  .function = vnet_ip_mroute_cmd,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

clib_error_t *
vnet_ip_container_proxy_add_del (vnet_ip_container_proxy_args_t * args)
{
  u32 fib_index;

  if (!vnet_sw_interface_is_api_valid (vnet_get_main (), args->sw_if_index))
    return clib_error_return_code (0, VNET_API_ERROR_INVALID_INTERFACE, 0,
				   "invalid sw_if_index");

  fib_index = fib_table_get_table_id_for_sw_if_index (args->prefix.fp_proto,
						      args->sw_if_index);
  if (args->is_add)
    {
      dpo_id_t proxy_dpo = DPO_INVALID;
      l3_proxy_dpo_add_or_lock (fib_proto_to_dpo (args->prefix.fp_proto),
				args->sw_if_index, &proxy_dpo);
      fib_table_entry_special_dpo_add (fib_index,
				       &args->prefix,
				       FIB_SOURCE_PROXY,
				       FIB_ENTRY_FLAG_EXCLUSIVE, &proxy_dpo);
      dpo_reset (&proxy_dpo);
    }
  else
    {
      fib_table_entry_special_remove (fib_index, &args->prefix,
				      FIB_SOURCE_PROXY);
    }
  return 0;
}

u8
ip_container_proxy_is_set (fib_prefix_t * pfx, u32 sw_if_index)
{
  u32 fib_index;
  fib_node_index_t fei;
  const dpo_id_t *dpo;
  l3_proxy_dpo_t *l3p;
  load_balance_t *lb0;

  fib_index = fib_table_get_table_id_for_sw_if_index (pfx->fp_proto,
						      sw_if_index);
  if (fib_index == ~0)
    return 0;

  fei = fib_table_lookup_exact_match (fib_index, pfx);
  if (fei == FIB_NODE_INDEX_INVALID)
    return 0;

  dpo = fib_entry_contribute_ip_forwarding (fei);
  lb0 = load_balance_get (dpo->dpoi_index);
  dpo = load_balance_get_bucket_i (lb0, 0);
  if (dpo->dpoi_type != DPO_L3_PROXY)
    return 0;

  l3p = l3_proxy_dpo_get (dpo->dpoi_index);
  return (l3p->l3p_sw_if_index == sw_if_index);
}

typedef struct ip_container_proxy_walk_ctx_t_
{
  ip_container_proxy_cb_t cb;
  void *ctx;
} ip_container_proxy_walk_ctx_t;

static fib_table_walk_rc_t
ip_container_proxy_fib_table_walk (fib_node_index_t fei, void *arg)
{
  ip_container_proxy_walk_ctx_t *ctx = arg;
  const fib_prefix_t *pfx;
  const dpo_id_t *dpo;
  load_balance_t *lb;
  l3_proxy_dpo_t *l3p;

  pfx = fib_entry_get_prefix (fei);
  if (fib_entry_is_sourced (fei, FIB_SOURCE_PROXY))
    {
      dpo = fib_entry_contribute_ip_forwarding (fei);
      lb = load_balance_get (dpo->dpoi_index);
      dpo = load_balance_get_bucket_i (lb, 0);
      l3p = l3_proxy_dpo_get (dpo->dpoi_index);
      ctx->cb (pfx, l3p->l3p_sw_if_index, ctx->ctx);
    }

  return FIB_TABLE_WALK_CONTINUE;
}

void
ip_container_proxy_walk (ip_container_proxy_cb_t cb, void *ctx)
{
  fib_table_t *fib_table;
  ip_container_proxy_walk_ctx_t wctx = {
    .cb = cb,
    .ctx = ctx,
  };

  /* *INDENT-OFF* */
  pool_foreach (fib_table, ip4_main.fibs,
  ({
    fib_table_walk(fib_table->ft_index,
                   FIB_PROTOCOL_IP4,
                   ip_container_proxy_fib_table_walk,
                   &wctx);
  }));
  pool_foreach (fib_table, ip6_main.fibs,
  ({
    fib_table_walk(fib_table->ft_index,
                   FIB_PROTOCOL_IP6,
                   ip_container_proxy_fib_table_walk,
                   &wctx);
  }));
  /* *INDENT-ON* */
}

clib_error_t *
ip_container_cmd (vlib_main_t * vm,
		  unformat_input_t * main_input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  fib_prefix_t pfx;
  u32 is_del, addr_set = 0;
  vnet_main_t *vnm;
  u32 sw_if_index;

  vnm = vnet_get_main ();
  is_del = 0;
  sw_if_index = ~0;
  clib_memset (&pfx, 0, sizeof (pfx));

  /* Get a line of input. */
  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_ip4_address, &pfx.fp_addr.ip4))
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP4;
	  pfx.fp_len = 32;
	  addr_set = 1;
	}
      else if (unformat (line_input, "%U",
			 unformat_ip6_address, &pfx.fp_addr.ip6))
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP6;
	  pfx.fp_len = 128;
	  addr_set = 1;
	}
      else if (unformat (line_input, "%U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "del"))
	is_del = 1;
      else
	{
	  unformat_free (line_input);
	  return (clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input));
	}
    }

  if (~0 == sw_if_index || !addr_set)
    {
      unformat_free (line_input);
      vlib_cli_output (vm, "interface and address must be set");
      return 0;
    }

  vnet_ip_container_proxy_args_t args = {
    .prefix = pfx,
    .sw_if_index = sw_if_index,
    .is_add = !is_del,
  };
  vnet_ip_container_proxy_add_del (&args);
  unformat_free (line_input);
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip_container_command_node, static) = {
  .path = "ip container",
  .function = ip_container_cmd,
  .short_help = "ip container <address> <interface>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

clib_error_t *
show_ip_container_cmd_fn (vlib_main_t * vm, unformat_input_t * main_input,
			  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  fib_prefix_t pfx;
  u32 sw_if_index = ~0;
  u8 has_proxy;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_ip4_address, &pfx.fp_addr.ip4))
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP4;
	  pfx.fp_len = 32;
	}
      else if (unformat (line_input, "%U",
			 unformat_ip6_address, &pfx.fp_addr.ip6))
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP6;
	  pfx.fp_len = 128;
	}
      else if (unformat (line_input, "%U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	{
	  unformat_free (line_input);
	  return (clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input));
	}
    }

  if (~0 == sw_if_index)
    {
      unformat_free (line_input);
      vlib_cli_output (vm, "no interface");
      return (clib_error_return (0, "no interface"));
    }

  has_proxy = ip_container_proxy_is_set (&pfx, sw_if_index);
  vlib_cli_output (vm, "ip container proxy is: %s", has_proxy ? "on" : "off");

  unformat_free (line_input);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip_container_command, static) = {
  .path = "show ip container",
  .function = show_ip_container_cmd_fn,
  .short_help = "show ip container <address> <interface>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */