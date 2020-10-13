/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#ifdef HAVE_OPENSSL_ASYNC
#include <openssl/async.h>
#endif
#include <dlfcn.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/tls/tls.h>
#include <ctype.h>
#include <tlsopenssl/tls_openssl.h>

#define MAX_CRYPTO_LEN 64

openssl_main_t openssl_main;
static u32
openssl_ctx_alloc (void)
{
  u8 thread_index = vlib_get_thread_index ();
  openssl_main_t *tm = &openssl_main;
  openssl_ctx_t **ctx;

  pool_get (tm->ctx_pool[thread_index], ctx);
  if (!(*ctx))
    *ctx = clib_mem_alloc (sizeof (openssl_ctx_t));

  clib_memset (*ctx, 0, sizeof (openssl_ctx_t));
  (*ctx)->ctx.c_thread_index = thread_index;
  (*ctx)->ctx.tls_ctx_engine = CRYPTO_ENGINE_OPENSSL;
  (*ctx)->ctx.app_session_handle = SESSION_INVALID_HANDLE;
  (*ctx)->openssl_ctx_index = ctx - tm->ctx_pool[thread_index];
  return ((*ctx)->openssl_ctx_index);
}

static void
openssl_ctx_free (tls_ctx_t * ctx)
{
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;

  if (SSL_is_init_finished (oc->ssl) && !ctx->is_passive_close)
    SSL_shutdown (oc->ssl);

  SSL_free (oc->ssl);

#ifdef HAVE_OPENSSL_ASYNC
  openssl_evt_free (ctx->evt_index, ctx->c_thread_index);
#endif
  vec_free (ctx->srv_hostname);
  pool_put_index (openssl_main.ctx_pool[ctx->c_thread_index],
		  oc->openssl_ctx_index);
}

tls_ctx_t *
openssl_ctx_get (u32 ctx_index)
{
  openssl_ctx_t **ctx;
  ctx = pool_elt_at_index (openssl_main.ctx_pool[vlib_get_thread_index ()],
			   ctx_index);
  return &(*ctx)->ctx;
}

tls_ctx_t *
openssl_ctx_get_w_thread (u32 ctx_index, u8 thread_index)
{
  openssl_ctx_t **ctx;
  ctx = pool_elt_at_index (openssl_main.ctx_pool[thread_index], ctx_index);
  return &(*ctx)->ctx;
}

static u32
openssl_listen_ctx_alloc (void)
{
  openssl_main_t *om = &openssl_main;
  openssl_listen_ctx_t *lctx;

  pool_get (om->lctx_pool, lctx);

  clib_memset (lctx, 0, sizeof (openssl_listen_ctx_t));
  lctx->openssl_lctx_index = lctx - om->lctx_pool;
  return lctx->openssl_lctx_index;
}

static void
openssl_listen_ctx_free (openssl_listen_ctx_t * lctx)
{
  pool_put_index (openssl_main.lctx_pool, lctx->openssl_lctx_index);
}

openssl_listen_ctx_t *
openssl_lctx_get (u32 lctx_index)
{
  return pool_elt_at_index (openssl_main.lctx_pool, lctx_index);
}

static int
openssl_read_from_bio_into_fifo (svm_fifo_t * f, BIO * bio, u32 enq_max)
{
  svm_fifo_chunk_t *c;
  int read, rv;
  u32 enq_now;

  svm_fifo_fill_chunk_list (f);

  enq_now = clib_min (svm_fifo_max_write_chunk (f), enq_max);
  if (!enq_now)
    return 0;

  read = BIO_read (bio, svm_fifo_tail (f), enq_now);
  if (read <= 0)
    return 0;

  c = svm_fifo_tail_chunk (f);
  while ((c = c->next) && read < enq_max)
    {
      enq_now = clib_min (c->length, enq_max - read);
      rv = BIO_read (bio, c->data, enq_now);
      read += rv > 0 ? rv : 0;

      if (rv < enq_now)
	break;
    }

  svm_fifo_enqueue_nocopy (f, read);

  return read;
}

static int
openssl_read_from_ssl_into_fifo (svm_fifo_t * f, SSL * ssl)
{
  u32 enq_now, enq_max;
  svm_fifo_chunk_t *c;
  int read, rv;

  enq_max = svm_fifo_max_enqueue_prod (f);
  if (!enq_max)
    return 0;

  svm_fifo_fill_chunk_list (f);

  enq_now = clib_min (svm_fifo_max_write_chunk (f), enq_max);
  if (!enq_now)
    return 0;

  read = SSL_read (ssl, svm_fifo_tail (f), enq_now);
  if (read <= 0)
    return 0;

  c = svm_fifo_tail_chunk (f);
  while ((c = c->next) && read < enq_max)
    {
      enq_now = clib_min (c->length, enq_max - read);
      rv = SSL_read (ssl, c->data, enq_now);
      read += rv > 0 ? rv : 0;

      if (rv < enq_now)
	break;
    }

  svm_fifo_enqueue_nocopy (f, read);

  return read;
}

static int
openssl_write_from_fifo_into_bio (svm_fifo_t * f, BIO * bio, u32 len)
{
  svm_fifo_chunk_t *c;
  int wrote, rv;
  u32 deq_now;

  deq_now = clib_min (svm_fifo_max_read_chunk (f), len);
  wrote = BIO_write (bio, svm_fifo_head (f), deq_now);
  if (wrote <= 0)
    return 0;

  c = svm_fifo_head_chunk (f);
  while ((c = c->next) && wrote < len)
    {
      deq_now = clib_min (c->length, len - wrote);
      rv = BIO_write (bio, c->data, deq_now);
      wrote += rv > 0 ? rv : 0;

      if (rv < deq_now)
	break;
    }

  svm_fifo_dequeue_drop (f, wrote);

  return wrote;
}

static int
openssl_write_from_fifo_into_ssl (svm_fifo_t * f, SSL * ssl, u32 len)
{
  svm_fifo_chunk_t *c;
  int wrote = 0, rv;
  u32 deq_now;

  deq_now = clib_min (svm_fifo_max_read_chunk (f), len);
  wrote = SSL_write (ssl, svm_fifo_head (f), deq_now);
  if (wrote <= 0)
    return 0;

  c = svm_fifo_head_chunk (f);
  while ((c = c->next) && wrote < len)
    {
      deq_now = clib_min (c->length, len - wrote);
      rv = SSL_write (ssl, c->data, deq_now);
      wrote += rv > 0 ? rv : 0;

      if (rv < deq_now)
	break;
    }

  svm_fifo_dequeue_drop (f, wrote);

  return wrote;
}

static int
openssl_try_handshake_read (openssl_ctx_t * oc, session_t * tls_session)
{
  svm_fifo_t *f;
  u32 deq_max;

  f = tls_session->rx_fifo;
  deq_max = svm_fifo_max_dequeue_cons (f);
  if (!deq_max)
    return 0;

  return openssl_write_from_fifo_into_bio (f, oc->wbio, deq_max);
}

static int
openssl_try_handshake_write (openssl_ctx_t * oc, session_t * tls_session)
{
  u32 read, enq_max;

  if (BIO_ctrl_pending (oc->rbio) <= 0)
    return 0;

  enq_max = svm_fifo_max_enqueue_prod (tls_session->tx_fifo);
  if (!enq_max)
    return 0;

  read = openssl_read_from_bio_into_fifo (tls_session->tx_fifo, oc->rbio,
					  enq_max);
  if (read)
    tls_add_vpp_q_tx_evt (tls_session);

  return read;
}

#ifdef HAVE_OPENSSL_ASYNC
static int
openssl_check_async_status (tls_ctx_t * ctx, openssl_resume_handler * handler,
			    session_t * session)
{
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  int estatus;

  SSL_get_async_status (oc->ssl, &estatus);
  if (estatus == ASYNC_STATUS_EAGAIN)
    {
      vpp_tls_async_update_event (ctx, 1);
    }
  else
    {
      vpp_tls_async_update_event (ctx, 0);
    }

  return 1;

}

#endif

static void
openssl_handle_handshake_failure (tls_ctx_t * ctx)
{
  session_t *app_session;

  if (SSL_is_server (((openssl_ctx_t *) ctx)->ssl))
    {
      /*
       * Cleanup pre-allocated app session and close transport
       */
      app_session =
	session_get_if_valid (ctx->c_s_index, ctx->c_thread_index);
      if (app_session)
	{
	  session_free (app_session);
	  ctx->no_app_session = 1;
	  ctx->c_s_index = SESSION_INVALID_INDEX;
	  tls_disconnect_transport (ctx);
	}
    }
  else
    {
      /*
       * Also handles cleanup of the pre-allocated session
       */
      tls_notify_app_connected (ctx, SESSION_E_TLS_HANDSHAKE);
    }
}

int
openssl_ctx_handshake_rx (tls_ctx_t * ctx, session_t * tls_session)
{
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  int rv = 0, err;

  while (SSL_in_init (oc->ssl))
    {
      if (ctx->resume)
	{
	  ctx->resume = 0;
	}
      else if (!openssl_try_handshake_read (oc, tls_session))
	break;

      rv = SSL_do_handshake (oc->ssl);
      err = SSL_get_error (oc->ssl, rv);

#ifdef HAVE_OPENSSL_ASYNC
      if (err == SSL_ERROR_WANT_ASYNC)
	{
	  openssl_check_async_status (ctx, openssl_ctx_handshake_rx,
				      tls_session);
	}
#endif
      if (err == SSL_ERROR_SSL)
	{
	  char buf[512];
	  ERR_error_string (ERR_get_error (), buf);
	  clib_warning ("Err: %s", buf);

	  openssl_handle_handshake_failure (ctx);
	  return -1;
	}

      openssl_try_handshake_write (oc, tls_session);

      if (err != SSL_ERROR_WANT_WRITE)
	break;
    }
  TLS_DBG (2, "tls state for %u is %s", oc->openssl_ctx_index,
	   SSL_state_string_long (oc->ssl));

  if (SSL_in_init (oc->ssl))
    return -1;

  /*
   * Handshake complete
   */
  if (!SSL_is_server (oc->ssl))
    {
      /*
       * Verify server certificate
       */
      if ((rv = SSL_get_verify_result (oc->ssl)) != X509_V_OK)
	{
	  TLS_DBG (1, " failed verify: %s\n",
		   X509_verify_cert_error_string (rv));

	  /*
	   * Presence of hostname enforces strict certificate verification
	   */
	  if (ctx->srv_hostname)
	    {
	      tls_notify_app_connected (ctx, SESSION_E_TLS_HANDSHAKE);
	      return -1;
	    }
	}
      tls_notify_app_connected (ctx, SESSION_E_NONE);
    }
  else
    {
      /* Need to check transport status */
      if (ctx->is_passive_close)
	openssl_handle_handshake_failure (ctx);
      else
	tls_notify_app_accept (ctx);
    }

  TLS_DBG (1, "Handshake for %u complete. TLS cipher is %s",
	   oc->openssl_ctx_index, SSL_get_cipher (oc->ssl));
  return rv;
}

static void
openssl_confirm_app_close (tls_ctx_t * ctx)
{
  tls_disconnect_transport (ctx);
  session_transport_closed_notify (&ctx->connection);
}

static inline int
openssl_ctx_write (tls_ctx_t * ctx, session_t * app_session,
		   transport_send_params_t * sp)
{
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  int wrote = 0, read, max_buf = 4 * TLS_CHUNK_SIZE, max_space, n_pending;
  u32 deq_max, to_write, enq_max;
  session_t *tls_session;
  svm_fifo_t *f;

  f = app_session->tx_fifo;

  deq_max = svm_fifo_max_dequeue_cons (f);
  if (!deq_max)
    goto check_tls_fifo;

  deq_max = clib_min (deq_max, sp->max_burst_size);

  /* Figure out how much data to write */
  max_space = max_buf - BIO_ctrl_pending (oc->rbio);
  max_space = (max_space < 0) ? 0 : max_space;
  to_write = clib_min (deq_max, (u32) max_space);

  wrote = openssl_write_from_fifo_into_ssl (f, oc->ssl, to_write);
  if (!wrote)
    goto check_tls_fifo;

  if (svm_fifo_needs_deq_ntf (f, wrote))
    session_dequeue_notify (app_session);

check_tls_fifo:

  if ((n_pending = BIO_ctrl_pending (oc->rbio)) <= 0)
    return wrote;

  tls_session = session_get_from_handle (ctx->tls_session_handle);

  enq_max = svm_fifo_max_enqueue_prod (tls_session->tx_fifo);
  if (!enq_max)
    goto maybe_reschedule;

  read = openssl_read_from_bio_into_fifo (tls_session->tx_fifo, oc->rbio,
					  enq_max);
  if (!read)
    goto maybe_reschedule;

  tls_add_vpp_q_tx_evt (tls_session);

  if (PREDICT_FALSE (ctx->app_closed && !BIO_ctrl_pending (oc->rbio)))
    openssl_confirm_app_close (ctx);

maybe_reschedule:

  if (!svm_fifo_max_enqueue_prod (tls_session->tx_fifo))
    {
      svm_fifo_add_want_deq_ntf (tls_session->tx_fifo,
				 SVM_FIFO_WANT_DEQ_NOTIF);
      transport_connection_deschedule (&ctx->connection);
      sp->flags |= TRANSPORT_SND_F_DESCHED;
    }
  else
    /* Request tx reschedule of the app session */
    app_session->flags |= SESSION_F_CUSTOM_TX;

  return wrote;
}

static inline int
openssl_ctx_read (tls_ctx_t * ctx, session_t * tls_session)
{
  int read, wrote = 0, max_space, max_buf = 4 * TLS_CHUNK_SIZE;
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  u32 deq_max, to_write;
  session_t *app_session;
  svm_fifo_t *f;

  if (PREDICT_FALSE (SSL_in_init (oc->ssl)))
    {
      if (openssl_ctx_handshake_rx (ctx, tls_session) < 0)
	return 0;
      else
	goto check_app_fifo;
    }

  f = tls_session->rx_fifo;

  deq_max = svm_fifo_max_dequeue_cons (f);
  max_space = max_buf - BIO_ctrl_pending (oc->wbio);
  max_space = max_space < 0 ? 0 : max_space;
  to_write = clib_min (deq_max, max_space);
  if (!to_write)
    goto check_app_fifo;

  wrote = openssl_write_from_fifo_into_bio (f, oc->wbio, to_write);
  if (!wrote)
    {
      tls_add_vpp_q_builtin_rx_evt (tls_session);
      goto check_app_fifo;
    }

  if (svm_fifo_max_dequeue_cons (f))
    tls_add_vpp_q_builtin_rx_evt (tls_session);

check_app_fifo:

  if (BIO_ctrl_pending (oc->wbio) <= 0)
    return wrote;

  app_session = session_get_from_handle (ctx->app_session_handle);
  f = app_session->rx_fifo;

  read = openssl_read_from_ssl_into_fifo (f, oc->ssl);
  if (!read)
    {
      tls_add_vpp_q_builtin_rx_evt (tls_session);
      return wrote;
    }

  /* If handshake just completed, session may still be in accepting state */
  if (app_session->session_state >= SESSION_STATE_READY)
    tls_notify_app_enqueue (ctx, app_session);
  if (SSL_pending (oc->ssl) > 0)
    tls_add_vpp_q_builtin_rx_evt (tls_session);

  return wrote;
}

static int
openssl_ctx_init_client (tls_ctx_t * ctx)
{
  long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  openssl_main_t *om = &openssl_main;
  session_t *tls_session;
  const SSL_METHOD *method;
  int rv, err;

  method = SSLv23_client_method ();
  if (method == NULL)
    {
      TLS_DBG (1, "SSLv23_method returned null");
      return -1;
    }

  oc->ssl_ctx = SSL_CTX_new (method);
  if (oc->ssl_ctx == NULL)
    {
      TLS_DBG (1, "SSL_CTX_new returned null");
      return -1;
    }

  SSL_CTX_set_ecdh_auto (oc->ssl_ctx, 1);
  SSL_CTX_set_mode (oc->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
#ifdef HAVE_OPENSSL_ASYNC
  if (om->async)
    SSL_CTX_set_mode (oc->ssl_ctx, SSL_MODE_ASYNC);
#endif
  rv = SSL_CTX_set_cipher_list (oc->ssl_ctx, (const char *) om->ciphers);
  if (rv != 1)
    {
      TLS_DBG (1, "Couldn't set cipher");
      return -1;
    }

  SSL_CTX_set_options (oc->ssl_ctx, flags);
  SSL_CTX_set_cert_store (oc->ssl_ctx, om->cert_store);

  oc->ssl = SSL_new (oc->ssl_ctx);
  if (oc->ssl == NULL)
    {
      TLS_DBG (1, "Couldn't initialize ssl struct");
      return -1;
    }

  oc->rbio = BIO_new (BIO_s_mem ());
  oc->wbio = BIO_new (BIO_s_mem ());

  BIO_set_mem_eof_return (oc->rbio, -1);
  BIO_set_mem_eof_return (oc->wbio, -1);

  SSL_set_bio (oc->ssl, oc->wbio, oc->rbio);
  SSL_set_connect_state (oc->ssl);

  rv = SSL_set_tlsext_host_name (oc->ssl, ctx->srv_hostname);
  if (rv != 1)
    {
      TLS_DBG (1, "Couldn't set hostname");
      return -1;
    }

  /*
   * 2. Do the first steps in the handshake.
   */
  TLS_DBG (1, "Initiating handshake for [%u]%u", ctx->c_thread_index,
	   oc->openssl_ctx_index);

  tls_session = session_get_from_handle (ctx->tls_session_handle);

#ifdef HAVE_OPENSSL_ASYNC
  vpp_tls_async_init_event (ctx, openssl_ctx_handshake_rx, tls_session);
#endif
  while (1)
    {
      rv = SSL_do_handshake (oc->ssl);
      err = SSL_get_error (oc->ssl, rv);
      openssl_try_handshake_write (oc, tls_session);
#ifdef HAVE_OPENSSL_ASYNC
      if (err == SSL_ERROR_WANT_ASYNC)
	{
	  openssl_check_async_status (ctx, openssl_ctx_handshake_rx,
				      tls_session);
	  break;
	}
#endif
      if (err != SSL_ERROR_WANT_WRITE)
	break;
    }

  TLS_DBG (2, "tls state for [%u]%u is su", ctx->c_thread_index,
	   oc->openssl_ctx_index, SSL_state_string_long (oc->ssl));
  return 0;
}

static int
openssl_start_listen (tls_ctx_t * lctx)
{
  const SSL_METHOD *method;
  SSL_CTX *ssl_ctx;
  int rv;
  BIO *cert_bio;
  X509 *srvcert;
  EVP_PKEY *pkey;
  u32 olc_index;
  openssl_listen_ctx_t *olc;
  app_cert_key_pair_t *ckpair;

  long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  openssl_main_t *om = &openssl_main;

  ckpair = app_cert_key_pair_get_if_valid (lctx->ckpair_index);
  if (!ckpair)
    return -1;

  if (!ckpair->cert || !ckpair->key)
    {
      TLS_DBG (1, "tls cert and/or key not configured %d",
	       lctx->parent_app_wrk_index);
      return -1;
    }

  method = SSLv23_method ();
  ssl_ctx = SSL_CTX_new (method);
  if (!ssl_ctx)
    {
      clib_warning ("Unable to create SSL context");
      return -1;
    }

  SSL_CTX_set_mode (ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
#ifdef HAVE_OPENSSL_ASYNC
  if (om->async)
    {
      SSL_CTX_set_mode (ssl_ctx, SSL_MODE_ASYNC);
      SSL_CTX_set_async_callback (ssl_ctx, tls_async_openssl_callback);
    }
#endif
  SSL_CTX_set_options (ssl_ctx, flags);
  SSL_CTX_set_ecdh_auto (ssl_ctx, 1);

  rv = SSL_CTX_set_cipher_list (ssl_ctx, (const char *) om->ciphers);
  if (rv != 1)
    {
      TLS_DBG (1, "Couldn't set cipher");
      return -1;
    }

  /*
   * Set the key and cert
   */
  cert_bio = BIO_new (BIO_s_mem ());
  BIO_write (cert_bio, ckpair->cert, vec_len (ckpair->cert));
  srvcert = PEM_read_bio_X509 (cert_bio, NULL, NULL, NULL);
  if (!srvcert)
    {
      clib_warning ("unable to parse certificate");
      return -1;
    }
  SSL_CTX_use_certificate (ssl_ctx, srvcert);
  BIO_free (cert_bio);

  cert_bio = BIO_new (BIO_s_mem ());
  BIO_write (cert_bio, ckpair->key, vec_len (ckpair->key));
  pkey = PEM_read_bio_PrivateKey (cert_bio, NULL, NULL, NULL);
  if (!pkey)
    {
      clib_warning ("unable to parse pkey");
      return -1;
    }
  SSL_CTX_use_PrivateKey (ssl_ctx, pkey);
  BIO_free (cert_bio);

  olc_index = openssl_listen_ctx_alloc ();
  olc = openssl_lctx_get (olc_index);
  olc->ssl_ctx = ssl_ctx;
  olc->srvcert = srvcert;
  olc->pkey = pkey;

  /* store SSL_CTX into TLS level structure */
  lctx->tls_ssl_ctx = olc_index;

  return 0;

}

static int
openssl_stop_listen (tls_ctx_t * lctx)
{
  u32 olc_index;
  openssl_listen_ctx_t *olc;

  olc_index = lctx->tls_ssl_ctx;
  olc = openssl_lctx_get (olc_index);

  X509_free (olc->srvcert);
  EVP_PKEY_free (olc->pkey);

  SSL_CTX_free (olc->ssl_ctx);
  openssl_listen_ctx_free (olc);

  return 0;
}

static int
openssl_ctx_init_server (tls_ctx_t * ctx)
{
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  u32 olc_index = ctx->tls_ssl_ctx;
  openssl_listen_ctx_t *olc;
  session_t *tls_session;
  int rv, err;

  /* Start a new connection */

  olc = openssl_lctx_get (olc_index);
  oc->ssl = SSL_new (olc->ssl_ctx);
  if (oc->ssl == NULL)
    {
      TLS_DBG (1, "Couldn't initialize ssl struct");
      return -1;
    }

  oc->rbio = BIO_new (BIO_s_mem ());
  oc->wbio = BIO_new (BIO_s_mem ());

  BIO_set_mem_eof_return (oc->rbio, -1);
  BIO_set_mem_eof_return (oc->wbio, -1);

  SSL_set_bio (oc->ssl, oc->wbio, oc->rbio);
  SSL_set_accept_state (oc->ssl);

  TLS_DBG (1, "Initiating handshake for [%u]%u", ctx->c_thread_index,
	   oc->openssl_ctx_index);

  tls_session = session_get_from_handle (ctx->tls_session_handle);
#ifdef HAVE_OPENSSL_ASYNC
  vpp_tls_async_init_event (ctx, openssl_ctx_handshake_rx, tls_session);
#endif
  while (1)
    {
      rv = SSL_do_handshake (oc->ssl);
      err = SSL_get_error (oc->ssl, rv);
      openssl_try_handshake_write (oc, tls_session);
#ifdef HAVE_OPENSSL_ASYNC
      if (err == SSL_ERROR_WANT_ASYNC)
	{
	  openssl_check_async_status (ctx, openssl_ctx_handshake_rx,
				      tls_session);
	  break;
	}
#endif
      if (err != SSL_ERROR_WANT_WRITE)
	break;
    }

  TLS_DBG (2, "tls state for [%u]%u is su", ctx->c_thread_index,
	   oc->openssl_ctx_index, SSL_state_string_long (oc->ssl));
  return 0;
}

static u8
openssl_handshake_is_over (tls_ctx_t * ctx)
{
  openssl_ctx_t *mc = (openssl_ctx_t *) ctx;
  if (!mc->ssl)
    return 0;
  return SSL_is_init_finished (mc->ssl);
}

static int
openssl_transport_close (tls_ctx_t * ctx)
{
#ifdef HAVE_OPENSSL_ASYNC
  if (vpp_openssl_is_inflight (ctx))
    return 0;
#endif

  if (!openssl_handshake_is_over (ctx))
    {
      openssl_handle_handshake_failure (ctx);
      return 0;
    }
  session_transport_closing_notify (&ctx->connection);
  return 0;
}

static int
openssl_app_close (tls_ctx_t * ctx)
{
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  session_t *app_session;

  /* Wait for all data to be written to tcp */
  app_session = session_get_from_handle (ctx->app_session_handle);
  if (BIO_ctrl_pending (oc->rbio) <= 0
      && !svm_fifo_max_dequeue_cons (app_session->tx_fifo))
    openssl_confirm_app_close (ctx);
  else
    ctx->app_closed = 1;
  return 0;
}

const static tls_engine_vft_t openssl_engine = {
  .ctx_alloc = openssl_ctx_alloc,
  .ctx_free = openssl_ctx_free,
  .ctx_get = openssl_ctx_get,
  .ctx_get_w_thread = openssl_ctx_get_w_thread,
  .ctx_init_server = openssl_ctx_init_server,
  .ctx_init_client = openssl_ctx_init_client,
  .ctx_write = openssl_ctx_write,
  .ctx_read = openssl_ctx_read,
  .ctx_handshake_is_over = openssl_handshake_is_over,
  .ctx_start_listen = openssl_start_listen,
  .ctx_stop_listen = openssl_stop_listen,
  .ctx_transport_close = openssl_transport_close,
  .ctx_app_close = openssl_app_close,
};

int
tls_init_ca_chain (void)
{
  openssl_main_t *om = &openssl_main;
  tls_main_t *tm = vnet_tls_get_main ();
  BIO *cert_bio;
  X509 *testcert;
  int rv;

  if (access (tm->ca_cert_path, F_OK | R_OK) == -1)
    {
      clib_warning ("Could not initialize TLS CA certificates");
      return -1;
    }

  if (!(om->cert_store = X509_STORE_new ()))
    {
      clib_warning ("failed to create cert store");
      return -1;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  rv = X509_STORE_load_file (om->cert_store, tm->ca_cert_path);
#else
  rv = X509_STORE_load_locations (om->cert_store, tm->ca_cert_path, 0);
#endif

  if (rv < 0)
    {
      clib_warning ("failed to load ca certificate");
    }

  if (tm->use_test_cert_in_ca)
    {
      cert_bio = BIO_new (BIO_s_mem ());
      BIO_write (cert_bio, test_srv_crt_rsa, test_srv_crt_rsa_len);
      testcert = PEM_read_bio_X509 (cert_bio, NULL, NULL, NULL);
      if (!testcert)
	{
	  clib_warning ("unable to parse certificate");
	  return -1;
	}
      X509_STORE_add_cert (om->cert_store, testcert);
      rv = 0;
    }
  return (rv < 0 ? -1 : 0);
}

int
tls_openssl_set_ciphers (char *ciphers)
{
  openssl_main_t *om = &openssl_main;
  int i;

  if (!ciphers)
    {
      return -1;
    }

  vec_validate (om->ciphers, strlen (ciphers) - 1);
  for (i = 0; i < vec_len (om->ciphers); i++)
    {
      om->ciphers[i] = toupper (ciphers[i]);
    }

  return 0;

}

static clib_error_t *
tls_openssl_init (vlib_main_t * vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  openssl_main_t *om = &openssl_main;
  clib_error_t *error = 0;
  u32 num_threads;

  error = tls_openssl_api_init (vm);
  num_threads = 1 /* main thread */  + vtm->n_threads;

  SSL_library_init ();
  SSL_load_error_strings ();

  if (tls_init_ca_chain ())
    {
      clib_warning ("failed to initialize TLS CA chain");
      return 0;
    }

  vec_validate (om->ctx_pool, num_threads - 1);

  tls_register_engine (&openssl_engine, CRYPTO_ENGINE_OPENSSL);

  om->engine_init = 0;

  /* default ciphers */
  tls_openssl_set_ciphers
    ("ALL:!ADH:!LOW:!EXP:!MD5:!RC4-SHA:!DES-CBC3-SHA:@STRENGTH");

  return error;
}
/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (tls_openssl_init) =
{
  .runs_after = VLIB_INITS("tls_init"),
};
/* *INDENT-ON* */

#ifdef HAVE_OPENSSL_ASYNC
static clib_error_t *
tls_openssl_set_command_fn (vlib_main_t * vm, unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  openssl_main_t *om = &openssl_main;
  char *engine_name = NULL;
  char *engine_alg = NULL;
  char *ciphers = NULL;
  u8 engine_name_set = 0;
  int i, async = 0;

  /* By present, it is not allowed to configure engine again after running */
  if (om->engine_init)
    {
      clib_warning ("engine has started!\n");
      return clib_error_return
	(0, "engine has started, and no config is accepted");
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "engine %s", &engine_name))
	{
	  engine_name_set = 1;
	}
      else if (unformat (input, "async"))
	{
	  async = 1;
	}
      else if (unformat (input, "alg %s", &engine_alg))
	{
	  for (i = 0; i < strnlen (engine_alg, MAX_CRYPTO_LEN); i++)
	    engine_alg[i] = toupper (engine_alg[i]);
	}
      else if (unformat (input, "ciphers %s", &ciphers))
	{
	  tls_openssl_set_ciphers (ciphers);
	}
      else
	return clib_error_return (0, "failed: unknown input `%U'",
				  format_unformat_error, input);
    }

  /* reset parameters if engine is not configured */
  if (!engine_name_set)
    {
      clib_warning ("No engine provided! \n");
      async = 0;
    }
  else
    {
      vnet_session_enable_disable (vm, 1);
      if (openssl_engine_register (engine_name, engine_alg, async) < 0)
	{
	  return clib_error_return (0, "Failed to register %s polling",
				    engine_name);
	}
      else
	{
	  vlib_cli_output (vm, "Successfully register engine %s\n",
			   engine_name);
	}
    }
  om->async = async;

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tls_openssl_set_command, static) =
{
  .path = "tls openssl set",
  .short_help = "tls openssl set [engine <engine name>] [alg [algorithm] [async]",
  .function = tls_openssl_set_command_fn,
};
/* *INDENT-ON* */
#endif

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Transport Layer Security (TLS) Engine, OpenSSL Based",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */