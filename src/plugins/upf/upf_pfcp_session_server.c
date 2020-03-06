/*
* Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

typedef enum
{
  EVENT_WAKEUP = 1,
} pfcp_process_event_t;

typedef struct
{
  u32 ps_index;
  u32 thread_index;
  u64 node_index;
} pfcp_session_server_args;

typedef enum
{
  PFCP_STATE_CLOSED,
  PFCP_STATE_ESTABLISHED,
  PFCP_STATE_OK_SENT,
} pfcp_session_state_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
#define _(type, name) type name;
  foreach_app_session_field
#undef _
  u32 thread_index;
  u8 *rx_buf;
  u32 vpp_session_index;
  u64 vpp_session_handle;
  u32 timer_handle;
} pfcp_session_t;

typedef struct
{
  pfcp_session_t **sessions;
  clib_rwlock_t sessions_lock;
  u32 **session_to_pfcp_session;

  svm_msg_q_t **vpp_queue;

  uword *handler_by_get_request;

  u32 *free_pfcp_cli_process_node_indices;

  /* Sever's event queue */
  svm_queue_t *vl_input_queue;

  /* API client handle */
  u32 my_client_index;

  u32 app_index;

  /* process node index for evnt scheduling */
  u32 node_index;

  tw_timer_wheel_2t_1w_2048sl_t tw;
  clib_spinlock_t tw_lock;

  u32 prealloc_fifos;
  u32 private_segment_size;
  u32 fifo_size;
  u8 *uri;
  vlib_main_t *vlib_main;
} pfcp_session_server_main_t;

pfcp_session_server_main_t pfcp_session_server_main;

static void
pfcp_session_server_sessions_reader_lock (void)
{
  clib_rwlock_reader_lock (&pfcp_session_server_main.sessions_lock);
}

static void
pfcp_session_server_sessions_reader_unlock (void)
{
  clib_rwlock_reader_unlock (&pfcp_session_server_main.sessions_lock);
}

static void
pfcp_session_server_sessions_writer_lock (void)
{
  clib_rwlock_writer_lock (&pfcp_session_server_main.sessions_lock);
}

static void
pfcp_session_server_sessions_writer_unlock (void)
{
  clib_rwlock_writer_unlock (&pfcp_session_server_main.sessions_lock);
}

static pfcp_session_t *
pfcp_session_server_session_alloc (u32 thread_index)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  pfcp_session_t *ps;
  pool_get (pssm->sessions[thread_index], ps);
  memset (ps, 0, sizeof (*ps));
  ps->session_index = ps - pssm->sessions[thread_index];
  ps->thread_index = thread_index;
  ps->timer_handle = ~0;
  return ps;
}

static pfcp_session_t *
pfcp_session_server_session_get (u32 thread_index, u32 ps_index)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  if (pool_is_free_index (pssm->sessions[thread_index], ps_index))
    return 0;
  return pool_elt_at_index (pssm->sessions[thread_index], ps_index);
}

static void
pfcp_session_server_session_free (pfcp_session_t * ps)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  pool_put (pssm->sessions[ps->thread_index], ps);
  if (CLIB_DEBUG)
    memset (ps, 0xfa, sizeof (*ps));
}

static void
pfcp_session_server_session_lookup_add (u32 thread_index, u32 s_index, u32 ps_index)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  vec_validate (pssm->session_to_pfcp_session[thread_index], s_index);
  pssm->session_to_pfcp_session[thread_index][s_index] = ps_index;
}

static void
pfcp_session_server_session_lookup_del (u32 thread_index, u32 s_index)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  pssm->session_to_pfcp_session[thread_index][s_index] = ~0;
}

static pfcp_session_t *
pfcp_session_server_session_lookup (u32 thread_index, u32 s_index)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  u32 ps_index;

  if (s_index < vec_len (pssm->session_to_pfcp_session[thread_index]))
    {
      ps_index = pssm->session_to_pfcp_session[thread_index][s_index];
      return pfcp_session_server_session_get (thread_index, ps_index);
    }
  return 0;
}


static void
pfcp_session_server_session_timer_start (pfcp_session_t * ps)
{
  u32 ps_handle;
  ps_handle = ps->thread_index << 24 | ps->session_index;
  clib_spinlock_lock (&pfcp_session_server_main.tw_lock);
  ps->timer_handle = tw_timer_start_2t_1w_2048sl (&pfcp_session_server_main.tw,
						  ps_handle, 0, 60);
  clib_spinlock_unlock (&pfcp_session_server_main.tw_lock);
}

static void
pfcp_session_server_session_timer_stop (pfcp_session_t * ps)
{
  if (ps->timer_handle == ~0)
    return;
  clib_spinlock_lock (&pfcp_session_server_main.tw_lock);
  tw_timer_stop_2t_1w_2048sl (&pfcp_session_server_main.tw, ps->timer_handle);
  clib_spinlock_unlock (&pfcp_session_server_main.tw_lock);
}

static void
pfcp_session_server_session_cleanup (pfcp_session_t * ps)
{
  if (!ps)
    return;
  pfcp_session_server_session_lookup_del (ps->thread_index, ps->vpp_session_index);
  vec_free (ps->rx_buf);
  pfcp_session_server_session_timer_stop (ps);
  pfcp_session_server_session_free (ps);
}

static void
pfcp_session_server_session_disconnect (pfcp_session_t * ps)
{
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  a->handle = ps->vpp_session_handle;
  a->app_index = pfcp_session_server_main.app_index;
  vnet_disconnect_session (a);
}

static void
pfcp_process_free (pfcp_session_server_args * args)
{
  vlib_node_runtime_t *rt;
  vlib_main_t *vm = &vlib_global_main;
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  vlib_node_t *n;
  u32 node_index;
  pfcp_session_server_args **save_args;

  node_index = args->node_index;
  ASSERT (node_index != 0);

  n = vlib_get_node (vm, node_index);
  rt = vlib_node_get_runtime (vm, n->index);
  save_args = vlib_node_get_runtime_data (vm, n->index);

  /* Reset process session pointer */
  clib_mem_free (*save_args);
  *save_args = 0;

  /* Turn off the process node */
  vlib_node_set_state (vm, rt->node_index, VLIB_NODE_STATE_DISABLED);

  /* add node index to the freelist */
  vec_add1 (pssm->free_pfcp_cli_process_node_indices, node_index);
}

/* *INDENT-OFF* */
static const char *pfcp_ok =
    "PFCP/1.1 200 OK\r\n";

static const char *pfcp_response =
    "Content-Type: text/html\r\n"
    "Expires: Mon, 11 Jan 1970 10:10:10 GMT\r\n"
    "Connection: close \r\n"
    "Pragma: no-cache\r\n"
    "Content-Length: %d\r\n\r\n%s";

static const char *pfcp_error_template =
    "PFCP/1.1 %s\r\n"
    "Content-Type: text/html\r\n"
    "Expires: Mon, 11 Jan 1970 10:10:10 GMT\r\n"
    "Connection: close\r\n"
    "Pragma: no-cache\r\n"
    "Content-Length: 0\r\n\r\n";

/* Header, including incantation to suppress favicon.ico requests */
static const char *html_header_template =
    "<html><head><title>%v</title></head>"
    "<link rel=\"icon\" href=\"data:,\">"
    "<body><pre>";

static const char *html_footer =
    "</pre></body></html>\r\n";

/* *INDENT-ON* */

static void
pfcp_cli_output (uword arg, u8 * buffer, uword buffer_bytes)
{
  u8 **output_vecp = (u8 **) arg;
  u8 *output_vec;
  u32 offset;

  output_vec = *output_vecp;

  offset = vec_len (output_vec);
  vec_validate (output_vec, offset + buffer_bytes - 1);
  clib_memcpy_fast (output_vec + offset, buffer, buffer_bytes);

  *output_vecp = output_vec;
}

void
send_data (pfcp_session_t * ps, u8 * data)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  vlib_main_t *vm = vlib_get_main ();
  f64 last_sent_timer = vlib_time_now (vm);
  u32 offset, bytes_to_send;
  f64 delay = 10e-3;

  bytes_to_send = vec_len (data);
  offset = 0;

  while (bytes_to_send > 0)
    {
      int actual_transfer;

      actual_transfer = svm_fifo_enqueue
	(ps->tx_fifo, bytes_to_send, data + offset);

      /* Made any progress? */
      if (actual_transfer <= 0)
	{
	  pfcp_session_server_sessions_reader_unlock ();
	  vlib_process_suspend (vm, delay);
	  pfcp_session_server_sessions_reader_lock ();

	  /* 10s deadman timer */
	  if (vlib_time_now (vm) > last_sent_timer + 10.0)
	    {
	      a->handle = ps->vpp_session_handle;
	      a->app_index = pssm->app_index;
	      vnet_disconnect_session (a);
	      break;
	    }
	  /* Exponential backoff, within reason */
	  if (delay < 1.0)
	    delay = delay * 2.0;
	}
      else
	{
	  last_sent_timer = vlib_time_now (vm);
	  offset += actual_transfer;
	  bytes_to_send -= actual_transfer;

	  if (svm_fifo_set_event (ps->tx_fifo))
	    session_send_io_evt_to_thread (ps->tx_fifo,
					   SESSION_IO_EVT_TX_FLUSH);
	  delay = 10e-3;
	}
    }
}

static void
send_error (pfcp_session_t * ps, char *str)
{
  u8 *data;

  data = format (0, pfcp_error_template, str);
  send_data (ps, data);
  vec_free (data);
}

static uword
pfcp_cli_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		  vlib_frame_t * f)
{
  u8 *request = 0, *reply = 0, *pfcp = 0, *html = 0;
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  pfcp_session_server_args **save_args;
  pfcp_session_server_args *args;
  unformat_input_t input;
  pfcp_session_t *ps;
  int i;

  save_args = vlib_node_get_runtime_data (pssm->vlib_main, rt->node_index);
  args = *save_args;

  pfcp_session_server_sessions_reader_lock ();

  ps = pfcp_session_server_session_get (args->thread_index, args->ps_index);
  ASSERT (ps);

  request = ps->rx_buf;
  if (vec_len (request) < 7)
    {
      send_error (ps, "400 Bad Request");
      goto out;
    }

  for (i = 0; i < vec_len (request) - 4; i++)
    {
      if (request[i] == 'G' &&
	  request[i + 1] == 'E' &&
	  request[i + 2] == 'T' && request[i + 3] == ' ')
	goto found;
    }
bad_request:
  send_error (ps, "400 Bad Request");
  goto out;

found:
  /* Lose "GET " */
  vec_delete (request, i + 5, 0);

  /* Replace slashes with spaces, stop at the end of the path */
  i = 0;
  while (1)
    {
      if (request[i] == '/')
	request[i] = ' ';
      else if (request[i] == ' ')
	{
	  /* vlib_cli_input is vector-based, no need for a NULL */
	  _vec_len (request) = i;
	  break;
	}
      i++;
      /* Should never happen */
      if (i == vec_len (request))
	goto bad_request;
    }

  /* Generate the html header */
  html = format (0, html_header_template, request /* title */ );

  /* Run the command */
  unformat_init_vector (&input, vec_dup (request));
  vlib_cli_input (vm, &input, pfcp_cli_output, (uword) & reply);
  unformat_free (&input);
  request = 0;

  /* Generate the html page */
  html = format (html, "%v", reply);
  html = format (html, html_footer);
  /* And the pfcp reply */
  pfcp = format (0, pfcp_ok);
  pfcp = format (pfcp, pfcp_response, vec_len (html), html);

  /* Send it */
  send_data (ps, pfcp);

out:
  /* Cleanup */
  pfcp_session_server_sessions_reader_unlock ();
  vec_free (reply);
  vec_free (html);
  vec_free (pfcp);

  pfcp_process_free (args);
  return (0);
}

static void
alloc_pfcp_process (pfcp_session_server_args * args)
{
  char *name;
  vlib_node_t *n;
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  vlib_main_t *vm = pssm->vlib_main;
  uword l = vec_len (pssm->free_pfcp_cli_process_node_indices);
  pfcp_session_server_args **save_args;

  if (vec_len (pssm->free_pfcp_cli_process_node_indices) > 0)
    {
      n = vlib_get_node (vm, pssm->free_pfcp_cli_process_node_indices[l - 1]);
      vlib_node_set_state (vm, n->index, VLIB_NODE_STATE_POLLING);
      _vec_len (pssm->free_pfcp_cli_process_node_indices) = l - 1;
    }
  else
    {
      static vlib_node_registration_t r = {
	.function = pfcp_cli_process,
	.type = VLIB_NODE_TYPE_PROCESS,
	.process_log2_n_stack_bytes = 16,
	.runtime_data_bytes = sizeof (void *),
      };

      name = (char *) format (0, "pfcp-cli-%d", l);
      r.name = name;
      vlib_register_node (vm, &r);
      vec_free (name);

      n = vlib_get_node (vm, r.index);
    }

  /* Save the node index in the args. It won't be zero. */
  args->node_index = n->index;

  /* Save the args (pointer) in the node runtime */
  save_args = vlib_node_get_runtime_data (vm, n->index);
  *save_args = clib_mem_alloc (sizeof (*args));
  clib_memcpy_fast (*save_args, args, sizeof (*args));

  vlib_start_process (vm, n->runtime_index);
}

static void
alloc_pfcp_process_callback (void *cb_args)
{
  alloc_pfcp_process ((pfcp_session_server_args *) cb_args);
}

static int
session_rx_request (pfcp_session_t * ps)
{
  u32 max_dequeue, cursize;
  int n_read;

  cursize = vec_len (ps->rx_buf);
  max_dequeue = svm_fifo_max_dequeue_cons (ps->rx_fifo);
  if (PREDICT_FALSE (max_dequeue == 0))
    return -1;

  vec_validate (ps->rx_buf, cursize + max_dequeue - 1);
  n_read = app_recv_stream_raw (ps->rx_fifo, ps->rx_buf + cursize,
				max_dequeue, 0, 0 /* peek */ );
  ASSERT (n_read == max_dequeue);
  if (svm_fifo_is_empty_cons (ps->rx_fifo))
    svm_fifo_unset_event (ps->rx_fifo);

  _vec_len (ps->rx_buf) = cursize + n_read;
  return 0;
}

static int
pfcp_session_server_rx_callback (session_t * s)
{
  pfcp_session_server_args args;
  pfcp_session_t *ps;
  int rv;

  pfcp_session_server_sessions_reader_lock ();

  ps = pfcp_session_server_session_lookup (s->thread_index, s->session_index);
  if (!ps || ps->session_state != PFCP_STATE_ESTABLISHED)
    return -1;

  rv = session_rx_request (ps);
  if (rv)
    return rv;

  /* send the command to a new/recycled vlib process */
  args.ps_index = ps->session_index;
  args.thread_index = ps->thread_index;

  pfcp_session_server_sessions_reader_unlock ();

  /* Send RPC request to main thread */
  if (vlib_get_thread_index () != 0)
    vlib_rpc_call_main_thread (alloc_pfcp_process_callback, (u8 *) & args,
			       sizeof (args));
  else
    alloc_pfcp_process (&args);
  return 0;
}

static int
pfcp_session_server_session_accept_callback (session_t * s)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  pfcp_session_t *ps;

  pssm->vpp_queue[s->thread_index] =
    session_main_get_vpp_event_queue (s->thread_index);

  pfcp_session_server_sessions_writer_lock ();

  ps = pfcp_session_server_session_alloc (s->thread_index);
  pfcp_session_server_session_lookup_add (s->thread_index, s->session_index,
				  ps->session_index);
  ps->rx_fifo = s->rx_fifo;
  ps->tx_fifo = s->tx_fifo;
  ps->vpp_session_index = s->session_index;
  ps->vpp_session_handle = session_handle (s);
  ps->session_state = PFCP_STATE_ESTABLISHED;
  pfcp_session_server_session_timer_start (ps);

  pfcp_session_server_sessions_writer_unlock ();

  s->session_state = SESSION_STATE_READY;
  return 0;
}

static void
pfcp_session_server_session_disconnect_callback (session_t * s)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  pfcp_session_t *ps;

  pfcp_session_server_sessions_writer_lock ();

  ps = pfcp_session_server_session_lookup (s->thread_index, s->session_index);
  pfcp_session_server_session_cleanup (ps);

  pfcp_session_server_sessions_writer_unlock ();

  a->handle = session_handle (s);
  a->app_index = pssm->app_index;
  vnet_disconnect_session (a);
}

static void
pfcp_session_server_session_reset_callback (session_t * s)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  pfcp_session_t *ps;

  pfcp_session_server_sessions_writer_lock ();

  ps = pfcp_session_server_session_lookup (s->thread_index, s->session_index);
  pfcp_session_server_session_cleanup (ps);

  pfcp_session_server_sessions_writer_unlock ();

  a->handle = session_handle (s);
  a->app_index = pssm->app_index;
  vnet_disconnect_session (a);
}

static int
pfcp_session_server_session_connected_callback (u32 app_index, u32 api_context,
					session_t * s, u8 is_fail)
{
  clib_warning ("called...");
  return -1;
}

static int
pfcp_session_server_add_segment_callback (u32 client_index, u64 segment_handle)
{
  clib_warning ("called...");
  return -1;
}

static session_cb_vft_t pfcp_session_server_session_cb_vft = {
  .session_accept_callback = pfcp_session_server_session_accept_callback,
  .session_disconnect_callback = pfcp_session_server_session_disconnect_callback,
  .session_connected_callback = pfcp_session_server_session_connected_callback,
  .add_segment_callback = pfcp_session_server_add_segment_callback,
  .builtin_app_rx_callback = pfcp_session_server_rx_callback,
  .session_reset_callback = pfcp_session_server_session_reset_callback
};

static int
pfcp_session_server_attach ()
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  u64 options[APP_OPTIONS_N_OPTIONS];
  vnet_app_attach_args_t _a, *a = &_a;
  u32 segment_size = 128 << 20;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  if (pssm->private_segment_size)
    segment_size = pssm->private_segment_size;

  a->api_client_index = ~0;
  a->name = format (0, "test_pfcp_session_server");
  a->session_cb_vft = &pfcp_session_server_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] =
    pssm->fifo_size ? pssm->fifo_size : 8 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] =
    pssm->fifo_size ? pssm->fifo_size : 32 << 10;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = pssm->prealloc_fifos;

  if (vnet_application_attach (a))
    {
      vec_free (a->name);
      clib_warning ("failed to attach server");
      return -1;
    }
  vec_free (a->name);
  pssm->app_index = a->app_index;

  return 0;
}

static int
pfcp_session_server_listen ()
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  vnet_listen_args_t _a, *a = &_a;
  clib_memset (a, 0, sizeof (*a));
  a->app_index = pssm->app_index;
  a->uri = "tcp://0.0.0.0/80";
  if (pssm->uri)
    a->uri = (char *) pssm->uri;
  return vnet_bind_uri (a);
}

static void
pfcp_session_server_session_cleanup_cb (void *ps_handlep)
{
  pfcp_session_t *ps;
  uword ps_handle;
  ps_handle = pointer_to_uword (ps_handlep);
  ps = pfcp_session_server_session_get (ps_handle >> 24, ps_handle & 0x00FFFFFF);
  if (!ps)
    return;
  ps->timer_handle = ~0;
  pfcp_session_server_session_disconnect (ps);
  pfcp_session_server_session_cleanup (ps);
}

static void
pfcp_expired_timers_dispatch (u32 * expired_timers)
{
  u32 ps_handle;
  int i;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      /* Get session handle. The first bit is the timer id */
      ps_handle = expired_timers[i] & 0x7FFFFFFF;
      session_send_rpc_evt_to_thread (ps_handle >> 24,
				      pfcp_session_server_session_cleanup_cb,
				      uword_to_pointer (ps_handle, void *));
    }
}

static uword
pfcp_session_server_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		     vlib_frame_t * f)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  f64 now, timeout = 1.0;
  uword *event_data = 0;
  uword __clib_unused event_type;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      now = vlib_time_now (vm);
      event_type = vlib_process_get_events (vm, (uword **) & event_data);

      /* expire timers */
      clib_spinlock_lock (&pfcp_session_server_main.tw_lock);
      tw_timer_expire_timers_2t_1w_2048sl (&pssm->tw, now);
      clib_spinlock_unlock (&pfcp_session_server_main.tw_lock);

      vec_reset_length (event_data);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (pfcp_session_server_process_node) =
{
  .function = pfcp_session_server_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "pfcp-server-process",
  .state = VLIB_NODE_STATE_DISABLED,
};
/* *INDENT-ON* */

static int
pfcp_session_server_create (vlib_main_t * vm)
{
  if (pfcp_session_server_attach ())
    {
      clib_warning ("failed to attach server");
      return -1;
    }
  if (pfcp_session_server_listen ())
    {
      clib_warning ("failed to start listening");
      return -1;
    }

  return 0;
}

static clib_error_t *
pfcp_session_server_set_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 prealloc_fifos = pssm->prealloc_fifos;
  u32 fifo_size = pssm->fifo_size;
  u64 seg_size = pssm->private_segment_size;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "prealloc-fifos %d", &prealloc_fifos))
	;
      else if (unformat (line_input, "private-segment-size %U",
			 unformat_memory_size, &seg_size))
	{
	  if (seg_size >= 0x100000000ULL)
	    {
	      vlib_cli_output (vm, "private segment size %llu, too large",
			       seg_size);
	      return 0;
	    }
	}
      else if (unformat (line_input, "fifo-size %d", &fifo_size))
	fifo_size <<= 10;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }
  unformat_free (line_input);

  if (pssm->my_client_index != (u32) ~ 0)
    return clib_error_return (0, "test pfcp server is already running");

  pssm->prealloc_fifos = prealloc_fifos;
  pssm->fifo_size = fifo_size;
  pssm->private_segment_size = seg_size;

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (pfcp_session_server_set_command, static) =
{
  .path = "upf pfcp server set",
  .short_help = "upf pfcp server set",
  .function = pfcp_session_server_set_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
pfcp_session_server_main_init (vlib_main_t * vm)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads;
  vlib_node_t *n;

  pssm->my_client_index = ~0;
  pssm->vlib_main = vm;

  /* PFPC server defaults */
  pssm->prealloc_fifos = 0;
  pssm->fifo_size = 64 << 10;
  pssm->private_segment_size = 0;

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (pssm->vpp_queue, num_threads - 1);
  vec_validate (pssm->sessions, num_threads - 1);
  vec_validate (pssm->session_to_pfcp_session, num_threads - 1);

  clib_rwlock_init (&pssm->sessions_lock);
  clib_spinlock_init (&pssm->tw_lock);

  /* Init timer wheel and process */
  tw_timer_wheel_init_2t_1w_2048sl (&pssm->tw, pfcp_expired_timers_dispatch,
				    1 /* timer interval */ , ~0);
  vlib_node_set_state (vm, pfcp_session_server_process_node.index,
		       VLIB_NODE_STATE_POLLING);
  n = vlib_get_node (vm, pfcp_session_server_process_node.index);
  vlib_start_process (vm, n->runtime_index);

  return 0;
}

VLIB_INIT_FUNCTION (pfcp_session_server_main_init);

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
