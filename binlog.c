/*
    This file is part of tgl-library

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    Copyright Vitaly Valtman 2013-2015
*/

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#if defined(WIN32) || defined(_WIN32)
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#include <io.h>
#include <sys/locking.h>
#else
#include <unistd.h>
#include <sys/file.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "crypto/bn.h"

#include "tgl-binlog.h"
#include "mtproto-common.h"
//#include "net.h"
#include "mtproto-client.h"
#include "mtproto-utils.h"

#include "tgl.h"
#include "auto.h"
#include "auto/auto-types.h"
#include "auto/auto-skip.h"
#include "auto/auto-store-ds.h"
#include "auto/auto-fetch-ds.h"
#include "auto/auto-free-ds.h"

#include "tgl-structures.h"
#include "tgl-methods-in.h"

#include "crypto/sha.h"

static int mystreq1 (const char *a, const char *b, int l) {
  if ((int)strlen (a) != l) { return 1; }
  return memcmp (a, b, l);
}

void bl_do_dc_option (struct tgl_state *TLS, int flags, int id, const char *name, int l1, const char *ip, int l2, int port) /* {{{ */ {
  struct tgl_dc *DC = TLS->DC_list[id];

/* {{{  DC option */
static int fetch_comb_binlog_dc_option (struct tgl_state *TLS, struct tl_ds_binlog_update *DS_U) {
  vlogprintf (E_NOTICE, "DC%d '%.*s' update: %.*s:%d\n",
    DS_LVAL (DS_U->dc),
    DS_RSTR (DS_U->name),
    DS_RSTR (DS_U->ip),
    DS_LVAL (DS_U->port)
  );

  tglmp_alloc_dc (TLS,
    0,
    DS_LVAL (DS_U->dc),
    DS_STR_DUP (DS_U->ip),
    DS_LVAL (DS_U->port)
  );
}
/* }}} */

static int fetch_comb_binlog_dc_option_new (struct tgl_state *TLS, struct tl_ds_binlog_update *DS_U) {
  vlogprintf (E_NOTICE, "DC%d '%.*s' update: %.*s:%d\n",
    DS_LVAL (DS_U->dc),
    DS_RSTR (DS_U->name),
    DS_RSTR (DS_U->ip),
    DS_LVAL (DS_U->port)
  );

  tglmp_alloc_dc (TLS,
    DS_LVAL (DS_U->flags),
    DS_LVAL (DS_U->dc),
    DS_STR_DUP (DS_U->ip),
    DS_LVAL (DS_U->port)
  );
  return 0;
}
/* }}} */

/* {{{ Auth key */
static int fetch_comb_binlog_auth_key (struct tgl_state *TLS, struct tl_ds_binlog_update *DS_U) {
  int num = DS_LVAL (DS_U->dc);
  assert (num >= 0 && num < TGL_MAX_DC_NUM);
  assert (TLS->DC_list[num]);

  tglf_fetch_int_tuple ((void *)TLS->DC_list[num]->auth_key, DS_U->key->key, 64);

  static unsigned char sha1_buffer[20];
  TGLC_sha1 ((void *)TLS->DC_list[num]->auth_key, 256, sha1_buffer);
  TLS->DC_list[num]->auth_key_id = *(long long *)(sha1_buffer + 12);

  TLS->DC_list[num]->flags |= TGLDCF_AUTHORIZED;
}
/* }}} */

/* {{{ Default dc */
static int fetch_comb_binlog_default_dc (struct tgl_state *TLS, struct tl_ds_binlog_update *DS_U) {
  int num = DS_LVAL (DS_U->dc);
  assert (num >= 0 && num < TGL_MAX_DC_NUM);
  TLS->DC_working = TLS->DC_list[num];
  TLS->dc_working_num = num;
  return 0;
}
/* }}} */

/* {{{ DC signed */
static int fetch_comb_binlog_dc_signed (struct tgl_state *TLS, struct tl_ds_binlog_update *DS_U) {
  int num = DS_LVAL (DS_U->dc);
  assert (num > 0 && num < TGL_MAX_DC_NUM);
  assert (TLS->DC_list[num]);
  TLS->DC_list[num]->flags |= TGLDCF_LOGGED_IN;
  return 0;
}
/* }}} */

  if (TLS->callback.our_id) {
    TLS->callback.our_id (TLS, TLS->our_id);
  }
}
/* }}} */

/* {{{ Set DH params */
static int fetch_comb_binlog_set_dh_params (struct tgl_state *TLS, struct tl_ds_binlog_update *DS_U) {
  if (TLS->encr_prime) { tfree (TLS->encr_prime, 256); BN_free (TLS->encr_prime_bn); }

void bl_do_set_dh_params (struct tgl_state *TLS, int root, unsigned char prime[], int version) /* {{{ */ {
  if (TLS->encr_prime) { tfree (TLS->encr_prime, 256); TGLC_bn_free (TLS->encr_prime_bn); }

  TLS->encr_prime_bn = BN_new ();
  BN_bin2bn ((void *)TLS->encr_prime, 256, TLS->encr_prime_bn);
  TLS->encr_param_version = DS_LVAL (DS_U->version);

  assert (tglmp_check_DH_params (TLS, TLS->encr_prime_bn, TLS->encr_root) >= 0);
}
/* }}} */

void bl_do_set_pts (struct tgl_state *TLS, int pts) /* {{{ */ {
  if (TLS->locks & TGL_LOCK_DIFF) { return; }
  if (pts <= TLS->pts) { return; }
  
  TLS->pts = pts;
}
/* }}} */

void bl_do_set_channel_pts (struct tgl_state *TLS, int id, int pts) /* {{{ */ {
  tgl_peer_t *E = tgl_peer_get (TLS, TGL_MK_CHANNEL (id));
  if (!E || !(E->flags & TGLPF_CREATED)) { return; }
  if (E->flags & TGLCHF_DIFF) { return ; }
  if (E->channel.pts <= pts) { return; }
  E->channel.pts = pts;
}
/* }}} */

void bl_do_set_qts (struct tgl_state *TLS, int qts) /* {{{ */ {
  if (TLS->locks & TGL_LOCK_DIFF) { return; }
  if (qts <= TLS->qts) { return; }
  
  TLS->qts = qts;
}
/* }}} */

void bl_do_set_date (struct tgl_state *TLS, int date) /* {{{ */ {
  if (TLS->locks & TGL_LOCK_DIFF) { return; }
  if (date <= TLS->date) { return; }
  
  TLS->date = date;
}
/* }}} */

/* {{{ delete user */
static int fetch_comb_binlog_user_delete (struct tgl_state *TLS, struct tl_ds_binlog_update *DS_U) {
  tgl_peer_id_t id = TGL_MK_USER (DS_LVAL (DS_U->id));
  tgl_peer_t *U = tgl_peer_get (TLS, id);
  assert (U);
  U->flags |= TGLUF_DELETED;

  if (TLS->callback.user_update) {
    TLS->callback.user_update (TLS, (void *)U, TGL_UPDATE_DELETED);
  }
  return 0;
}
/* }}} */

void bl_do_set_msg_id (struct tgl_state *TLS, tgl_message_id_t *old_id, tgl_message_id_t *new_id) /* {{{ */ {
  if (!memcmp (old_id, new_id, sizeof (tgl_message_id_t))) {
    return;
  }

  struct tgl_message *M = tgl_message_get (TLS, old_id);
  assert (M);
  
  
  if (M->flags & TGLMF_PENDING) {
    tglm_message_remove_unsent (TLS, M);
    M->flags &= ~TGLMF_PENDING;
  }

  if (TLS->callback.secret_chat_update) {
    TLS->callback.secret_chat_update (TLS, U, TGL_UPDATE_DELETED);
  }

  M->server_id = new_id->id;
}
/* }}} */

void bl_do_chat_add_user (struct tgl_state *TLS, tgl_peer_id_t id, int version, int user, int inviter, int date) /* {{{ */ {
  tgl_peer_t *P = tgl_peer_get (TLS, id);
  if (!P || !(P->flags & TGLPF_CREATED)) { return; }

  struct tgl_chat *C = &P->chat;
  if (C->user_list_version >= version || !C->user_list_version) { return; }

  int i;
  for (i = 0; i < C->user_list_size; i++) {
    if (C->user_list[i].user_id == user) { 
      return;
    }
  }

  struct tgl_user *U = (void *)_U;

  if ((flags & 0xff) != (U->flags & 0xff)) {
    updates |= TGL_UPDATE_FLAGS;
  }
  U->flags = flags & 0xffff;

  if (DS_U->access_hash) {
    U->access_hash = DS_LVAL (DS_U->access_hash);
    updates |= TGL_UPDATE_ACCESS_HASH;
  }
}
/* }}} */

void bl_do_chat_del_user (struct tgl_state *TLS, tgl_peer_id_t id, int version, int user) /* {{{ */ {
  tgl_peer_t *P = tgl_peer_get (TLS, id);
  if (!P || !(P->flags & TGLPF_CREATED)) { return; }

    if (U->print_name) {
      tglp_peer_delete_name (TLS, (void *)U);
      tfree_str (U->print_name);
    }
  }
  if (C->user_list[C->user_list_size - 1].user_id != user) { return; }

  assert (C->user_list[C->user_list_size - 1].user_id == user);
  C->user_list_size --;
  C->user_list = trealloc (C->user_list, 12 * C->user_list_size + 12, 12 * C->user_list_size);
  C->user_list_version = version;
  
  if (TLS->callback.chat_update) {
    TLS->callback.chat_update (TLS, C, TGL_UPDATE_MEMBERS);
  }
}
/* }}} */

void bl_do_edit_message (struct tgl_state *TLS, tgl_message_id_t *id, tgl_peer_id_t *from_id, tgl_peer_id_t *to_id, tgl_peer_id_t *fwd_from_id, int *fwd_date, int *date, const char *message, int message_len, struct tl_ds_message_media *media, struct tl_ds_message_action *action, int *reply_id, struct tl_ds_reply_markup *reply_markup, struct tl_ds_vector *entities, int flags) /* {{{ */ {
  assert (!(flags & 0xfffe0000));
  
  struct tgl_message *M = tgl_message_get (TLS, id);
  
  assert (flags & TGLMF_CREATED);
  assert (!(flags & TGLMF_ENCRYPTED));

  if (flags & (1 << 16)) {
    if (!M) {
      M = tglm_message_alloc (TLS, id);
    }
    M->server_id = id->id;
    assert (!(M->flags & TGLMF_CREATED));
  } else {
    assert (M->flags & TGLMF_CREATED);
  }

  assert (M);
  assert (!(M->flags & TGLMF_ENCRYPTED));

  if ((M->flags & TGLMF_PENDING) && !(flags & TGLMF_PENDING)){
    tglm_message_remove_unsent (TLS, M);
  }

  if (DS_U->last_read_in) {
    U->last_read_in = DS_LVAL (DS_U->last_read_in);
    tgls_messages_mark_read (TLS, U->last, 0, U->last_read_in);
  }

  if (DS_U->last_read_out) {
    U->last_read_out = DS_LVAL (DS_U->last_read_out);
    tgls_messages_mark_read (TLS, U->last, TGLMF_OUT, U->last_read_out);
  }

  if (to_id) {
    assert (flags & 0x10000);
    M->to_id = *to_id;
  }

  if (date) {
    M->date = *date;
  }

  return 0;
}

static int fetch_comb_binlog_encr_chat_new (struct tgl_state *TLS, struct tl_ds_binlog_update *DS_U) {
  tgl_peer_id_t id = TGL_MK_ENCR_CHAT (DS_LVAL (DS_U->id));
  tgl_peer_t *_U = tgl_peer_get (TLS, id);

  int flags = DS_LVAL (DS_U->flags);

  unsigned updates = 0;

  if (message) {
    M->message_len = message_len;
    M->message = tstrndup (message, message_len);
    assert (!(M->flags & TGLMF_SERVICE));
  }

  struct tgl_secret_chat *U = (void *)_U;

  if ((flags & 0xff) != (U->flags & 0xff)) {
    updates |= TGL_UPDATE_FLAGS;
  }

  if (entities) {
    tglf_fetch_message_entities (TLS, M, entities);
  }

  if (reply_id) {
    M->reply_id = *reply_id;
  }

  if (flags & 0x10000) {
    tglm_message_insert (TLS, M);
  }

  if (!(flags & TGLMF_UNREAD) && (M->flags & TGLMF_UNREAD)) {
    tgls_messages_mark_read (TLS, M, M->flags & TGLMF_OUT, M->permanent_id.id);
  }

  if (reply_markup) {
    M->reply_markup = tglf_fetch_alloc_reply_markup (TLS, M->next, reply_markup);
  }

  if (M->flags & TGLMF_PENDING) {
    tgls_message_change_random_id (TLS, M, M->permanent_id.id);
  }
  
  if (!M->temp_id) {
    tgls_message_change_temp_id (TLS, M, ++TLS->last_temp_id);
  }
}
/* }}} */

  tgl_peer_t *Us = tgl_peer_get (TLS, TGL_MK_USER (U->user_id));

  if (!U->print_name) {
    if (Us) {
      U->print_name = TLS->callback.create_print_name (TLS, id, "!", Us->user.first_name, Us->user.last_name, 0);
    } else {
      assert (!(M->flags & TGLMF_CREATED));
    }
    assert (!(M->flags & TGLMF_CREATED));
  } else {
    assert (M->flags & TGLMF_CREATED);
  }

  assert (flags & TGLMF_CREATED);
  assert (flags & TGLMF_ENCRYPTED);

  if ((M->flags & TGLMF_PENDING) && !(flags & TGLMF_PENDING)){
    tglm_message_remove_unsent (TLS, M);
  }
  if (!(M->flags & TGLMF_PENDING) && (flags & TGLMF_PENDING)){
    tglm_message_insert_unsent (TLS, M);
  }

  if (DS_U->state) {
    if (U->state == sc_waiting && DS_LVAL (DS_U->state) == sc_ok) {
      tgl_do_create_keys_end (TLS, U);
    }
    if ((int)U->state != DS_LVAL (DS_U->state)) {
      switch (DS_LVAL (DS_U->state)) {
      case sc_request:
        updates |= TGL_UPDATE_REQUESTED;
        break;
      case sc_ok:
        updates |= TGL_UPDATE_WORKING;
        vlogprintf (E_WARNING, "Secret chat in ok state\n");
        break;
      default:
        break;
      }
    }
    U->state = DS_LVAL (DS_U->state);
  }

  if (TLS->callback.secret_chat_update && updates) {
    TLS->callback.secret_chat_update (TLS, U, updates);
  }

  return 0;
}

  if (date) {
    M->date = *date;
  }

  struct tgl_secret_chat *E = (void *)tgl_peer_get (TLS, M->to_id);
  assert (E);

  if (action) {
    tglf_fetch_message_action_encrypted (TLS, &M->action, action);
    M->flags |= TGLMF_SERVICE;
  }

  if (flags & (1 << 16)) {
    if (!_U) {
      _U = talloc0 (sizeof (*_U));
      _U->id = id;
      tglp_insert_chat (TLS, _U);
    } else {
      assert (!(_U->flags & TGLPF_CREATED));
    }
    updates |= TGL_UPDATE_CREATED;
  } else {
    assert (_U->flags & TGLPF_CREATED);
  }

  struct tgl_chat *C = &_U->chat;

  if ((flags & 0xff) != (C->flags & 0xff)) {
    updates |= TGL_UPDATE_FLAGS;
  }
  C->flags = flags & 0xffff;

  if (DS_U->title) {
    if (C->title) {
      tfree_str (C->title);
    }
    C->title = DS_STR_DUP (DS_U->title);

    if (C->print_title) {
      tglp_peer_delete_name (TLS, (void *)C);
      tfree_str (C->print_title);
    }
    C->print_title = TLS->callback.create_print_name (TLS, C->id, C->title, 0, 0, 0);
    tglp_peer_insert_name (TLS, (void *)C);

    updates |= TGL_UPDATE_TITLE;
  }

  if (DS_U->user_num) {
    C->users_num = DS_LVAL (DS_U->user_num);
  }

  if (DS_U->date) {
    C->date = DS_LVAL (DS_U->date);
  }

  if (DS_U->chat_photo) {
    tglf_fetch_file_location_new (TLS, &C->photo_big, DS_U->chat_photo->photo_big);
    tglf_fetch_file_location_new (TLS, &C->photo_small, DS_U->chat_photo->photo_small);
    updates |= TGL_UPDATE_PHOTO;
  }

  if (DS_U->photo) {
    if (C->photo) {
      tgls_free_photo (TLS, C->photo);
    }
    C->photo = tglf_fetch_alloc_photo_new (TLS, DS_U->photo);
    C->flags |= TGLPF_HAS_PHOTO;
    updates |= TGL_UPDATE_PHOTO;
  }

  if (DS_U->admin) {
    C->admin_id = DS_LVAL (DS_U->admin);
    updates |= TGL_UPDATE_ADMIN;
  }

  if (DS_U->version) {
    C->version = DS_LVAL (DS_U->version);

    if (C->user_list) { tfree (C->user_list, 12 * C->user_list_size); }

    C->user_list_size = DS_LVAL (DS_U->participants->cnt);
    C->user_list = talloc (12 * C->user_list_size);

    int i;
    for (i = 0; i < C->user_list_size; i++) {
      C->user_list[i].user_id = DS_LVAL (DS_U->participants->data[i]->user_id);
      C->user_list[i].inviter_id = DS_LVAL (DS_U->participants->data[i]->inviter_id);
      C->user_list[i].date = DS_LVAL (DS_U->participants->data[i]->date);
    }

    updates |= TGL_UPDATE_MEMBERS;
  }

  if (DS_U->last_read_in) {
    C->last_read_in = DS_LVAL (DS_U->last_read_in);
    tgls_messages_mark_read (TLS, C->last, 0, C->last_read_in);
  }

  if (DS_U->last_read_out) {
    C->last_read_out = DS_LVAL (DS_U->last_read_out);
    tgls_messages_mark_read (TLS, C->last, TGLMF_OUT, C->last_read_out);
  }


  if (TLS->callback.chat_update && updates) {
    TLS->callback.chat_update (TLS, C, updates);
  }
  return 0;
}

static int fetch_comb_binlog_chat_add_participant (struct tgl_state *TLS, struct tl_ds_binlog_update *DS_U) {
  tgl_peer_id_t id = TGL_MK_CHAT (DS_LVAL (DS_U->id));
  tgl_peer_t *_C = tgl_peer_get (TLS, id);
  assert (_C && (_C->flags & TGLPF_CREATED));
  struct tgl_chat *C = &_C->chat;

  int version = DS_LVAL (DS_U->version);
  int user = DS_LVAL (DS_U->user_id);
  int inviter = DS_LVAL (DS_U->inviter_id);
  int date = DS_LVAL (DS_U->date);


  if (C->user_list_version > version) { return 0; }

  int i;
  for (i = 0; i < C->user_list_size; i++) {
    if (C->user_list[i].user_id == user) {
      return 0;
    }
  }

  C->user_list_size ++;
  C->user_list = trealloc (C->user_list, 12 * C->user_list_size - 12, 12 * C->user_list_size);
  C->user_list[C->user_list_size - 1].user_id = user;
  C->user_list[C->user_list_size - 1].inviter_id = inviter;
  C->user_list[C->user_list_size - 1].date = date;
  C->user_list_version = version;

  if (TLS->callback.chat_update) {
    TLS->callback.chat_update (TLS, C, TGL_UPDATE_MEMBERS);
  }
  return 0;
}

static int fetch_comb_binlog_chat_del_participant (struct tgl_state *TLS, struct tl_ds_binlog_update *DS_U) {
  tgl_peer_id_t id = TGL_MK_CHAT (DS_LVAL (DS_U->id));
  tgl_peer_t *_C = tgl_peer_get (TLS, id);
  assert (_C && (_C->flags & TGLPF_CREATED));
  struct tgl_chat *C = &_C->chat;

  int version = DS_LVAL (DS_U->version);
  int user = DS_LVAL (DS_U->user_id);
  if (C->user_list_version > version) { return 0; }

  int i;
  for (i = 0; i < C->user_list_size; i++) {
    if (C->user_list[i].user_id == user) {
      struct tgl_chat_user t;
      t = C->user_list[i];
      C->user_list[i] = C->user_list[C->user_list_size - 1];
      C->user_list[C->user_list_size - 1] = t;
    }
  }
  if (C->user_list[C->user_list_size - 1].user_id != user) { return 0; }

  assert (C->user_list[C->user_list_size - 1].user_id == user);
  C->user_list_size --;
  C->user_list = trealloc (C->user_list, 12 * C->user_list_size + 12, 12 * C->user_list_size);
  C->user_list_version = version;

  if (TLS->callback.chat_update) {
    TLS->callback.chat_update (TLS, C, TGL_UPDATE_MEMBERS);
  }
  return 0;
}

static int fetch_comb_binlog_message_new (struct tgl_state *TLS, struct tl_ds_binlog_update *DS_U) {
  struct tgl_message *M = tgl_message_get (TLS, DS_LVAL (DS_U->lid));
  int flags = DS_LVAL (DS_U->flags);

  if (flags & (1 << 16)) {
    if (!M) {
      M = tglm_message_alloc (TLS, DS_LVAL (DS_U->lid));
    }
    assert (!(M->flags & TGLMF_CREATED));
  } else {
    assert (M->flags & TGLMF_CREATED);
  }

  assert (flags & TGLMF_CREATED);
  assert (!(M->flags & TGLMF_ENCRYPTED));
  assert (!(flags & TGLMF_ENCRYPTED));

  if ((M->flags & TGLMF_PENDING) && !(flags & TGLMF_PENDING)){
    tglm_message_remove_unsent (TLS, M);
  }
  if (!(M->flags & TGLMF_PENDING) && (flags & TGLMF_PENDING)){
    tglm_message_insert_unsent (TLS, M);
  }

  if ((M->flags & TGLMF_UNREAD) && !(flags & TGLMF_UNREAD)) {
    M->flags = (flags & 0xffff) | TGLMF_UNREAD;
  } else {
    M->flags = (flags & 0xffff);
  }

  if (DS_U->from_id) {
    M->from_id = TGL_MK_USER (DS_LVAL (DS_U->from_id));
  }
  if (DS_U->to_type) {
    assert (flags & 0x10000);
    M->to_id = tgl_set_peer_id (DS_LVAL (DS_U->to_type), DS_LVAL (DS_U->to_id));
    assert (DS_LVAL (DS_U->to_type) != TGL_PEER_ENCR_CHAT);
  }

  if (DS_U->date) {
    M->date = DS_LVAL (DS_U->date);
  }

  if (DS_U->fwd_from_id) {
    M->fwd_from_id = TGL_MK_USER (DS_LVAL (DS_U->fwd_from_id));
    M->fwd_date = DS_LVAL (DS_U->fwd_date);
  }

  if (DS_U->action) {
    tglf_fetch_message_action_new (TLS, &M->action, DS_U->action);
    M->flags |= TGLMF_SERVICE;
  }

  if (DS_U->message) {
    M->message_len = DS_U->message->len;
    M->message = DS_STR_DUP (DS_U->message);
    assert (!(M->flags & TGLMF_SERVICE));
  }

  if (DS_U->media) {
    tglf_fetch_message_media_new (TLS, &M->media, DS_U->media);
    assert (!(M->flags & TGLMF_SERVICE));
  }

  if (DS_U->reply_id) {
    M->reply_id = DS_LVAL (DS_U->reply_id);
  }

  if (flags & 0x10000) {
    tglm_message_insert (TLS, M);
  }

  if (!(flags & TGLMF_UNREAD) && (M->flags & TGLMF_UNREAD)) {
    tgls_messages_mark_read (TLS, M, M->flags & TGLMF_OUT, M->id);
  }

  if (DS_U->reply_markup) {
    M->reply_markup = tglf_fetch_alloc_reply_markup (TLS, M->next, DS_U->reply_markup);
  }
  return 0;
}

static int fetch_comb_binlog_message_encr_new (struct tgl_state *TLS, struct tl_ds_binlog_update *DS_U) {
  struct tgl_message *M = tgl_message_get (TLS, DS_LVAL (DS_U->lid));
  int flags = DS_LVAL (DS_U->flags);

  if (flags & (1 << 16)) {
    if (!M) {
      M = tglm_message_alloc (TLS, DS_LVAL (DS_U->lid));
    } else {
      assert (!(M->flags & TGLMF_CREATED));
    }
    assert (!(M->flags & TGLMF_CREATED));
  } else {
    assert (M->flags & TGLMF_CREATED);
  }

  assert (flags & TGLMF_CREATED);
  assert (flags & TGLMF_ENCRYPTED);

  if ((M->flags & TGLMF_PENDING) && !(flags & TGLMF_PENDING)){
    tglm_message_remove_unsent (TLS, M);
  }
  if (!(M->flags & TGLMF_PENDING) && (flags & TGLMF_PENDING)){
    tglm_message_insert_unsent (TLS, M);
  }

  M->flags = flags & 0xffff;

  if (DS_U->from_id) {
    M->from_id = TGL_MK_USER (DS_LVAL (DS_U->from_id));
  }
  if (DS_U->to_type) {
    assert (flags & 0x10000);
    M->to_id = tgl_set_peer_id (DS_LVAL (DS_U->to_type), DS_LVAL (DS_U->to_id));
  }

  if (DS_U->date) {
    M->date = DS_LVAL (DS_U->date);
  }

  struct tgl_secret_chat *E = (void *)tgl_peer_get (TLS, M->to_id);
  assert (E);

  if (DS_U->message) {
    M->message_len = DS_U->message->len;
    M->message = DS_STR_DUP (DS_U->message);
    assert (!(M->flags & TGLMF_SERVICE));
  }

  if (media) {
    tglf_fetch_message_media_encrypted (TLS, &M->media, media);
    assert (!(M->flags & TGLMF_SERVICE));
  }

  if (file) {
    tglf_fetch_encrypted_message_file (TLS, &M->media, file);
    assert (!(M->flags & TGLMF_SERVICE));
  }

  if (action && !(M->flags & TGLMF_OUT) && M->action.type == tgl_message_action_notify_layer) {
    E->layer = M->action.layer;
  }

  if ((flags & TGLMF_CREATE) && (flags & TGLMF_OUT)) {
    E->out_seq_no ++;
  }

  if (flags & 0x10000) {
    tglm_message_insert (TLS, M);
  }
}
/* }}} */

void bl_do_message_delete (struct tgl_state *TLS, tgl_message_id_t *id) /* {{{ */ {
  struct tgl_message *M = tgl_message_get (TLS, id);
  if (!M) { return; }
  assert (M);
  if (M->flags & TGLMF_PENDING) {
    tglm_message_remove_unsent (TLS, M);
    M->flags &= ~TGLMF_PENDING;
  }

  tglm_message_remove_tree (TLS, M);
  tglm_message_del_peer (TLS, M);

  M->id = DS_LVAL (DS_U->new_id);
  if (tgl_message_get (TLS, M->id)) {
    tglm_message_del_use (TLS, M);
    tgls_free_message (TLS, M);
  } else {
    tglm_message_insert_tree (TLS, M);
    tglm_message_add_peer (TLS, M);
  }
  return 0;
}

  tglm_message_remove_tree (TLS, M);
  tglm_message_del_peer (TLS, M);
  tglm_message_del_use (TLS, M);
  tglm_message_del_temp_id (TLS, M);
  tglm_message_del_random_id (TLS, M);
  tgls_free_message (TLS, M);
}
/* }}} */

void bl_do_msg_update (struct tgl_state *TLS, tgl_message_id_t *id) /* {{{ */ {
  struct tgl_message *M = tgl_message_get (TLS, id);
  if (!M) { return; }
  assert (M);

  if (!(M->flags & TGLMF_ENCRYPTED)) {
    if (TLS->max_msg_id < M->server_id) {
      TLS->max_msg_id = M->server_id;
    }
  }

  if (TLS->callback.msg_receive) {
    TLS->callback.msg_receive (TLS, M);
  }
}
/* }}} */

void bl_do_reset_authorization (struct tgl_state *TLS) /* {{{ */ {
  int i;
  for (i = 0; i <= TLS->max_dc_num; i++) if (TLS->DC_list[i]) {
    struct tgl_dc *D = TLS->DC_list[i];
    D->flags = 0;
    D->state = st_init;
    D->auth_key_id = D->temp_auth_key_id = 0;
  }
  TLS->seq = 0;
  TLS->qts = 0;
}
/* }}} */

void bl_do_encr_chat_exchange (struct tgl_state *TLS, tgl_peer_id_t id, long long *exchange_id, const void *key, int *state) /* {{{ */ {
  tgl_peer_t *P = tgl_peer_get (TLS, id);
  if (!P) { return; }
  
  if (state) {
    P->encr_chat.exchange_state = *state;
  }
  if (exchange_id) {
    P->encr_chat.exchange_id = *exchange_id;
  }

  static unsigned char sha_buffer[20];
  switch (P->encr_chat.exchange_state) {
  case tgl_sce_requested:
    memcpy (P->encr_chat.exchange_key, key, 256);
    break;
  case tgl_sce_accepted:
    tglf_fetch_int_tuple (P->encr_chat.exchange_key, DS_U->key->key, 64);

    SHA1 ((unsigned char *)P->encr_chat.exchange_key, 256, sha_buffer);
    P->encr_chat.exchange_key_fingerprint = *(long long *)(sha_buffer + 12);
    break;
  case tgl_sce_committed:
    memcpy (P->encr_chat.exchange_key, P->encr_chat.key, 256);
    P->encr_chat.exchange_key_fingerprint = P->encr_chat.key_fingerprint;

    tglf_fetch_int_tuple (P->encr_chat.key, DS_U->key->key, 64);

    SHA1 ((unsigned char *)P->encr_chat.key, 256, sha_buffer);
    P->encr_chat.key_fingerprint = *(long long *)(sha_buffer + 12);
    break;
  case tgl_sce_confirmed:
    P->encr_chat.exchange_state = tgl_sce_none;
    if (P->encr_chat.exchange_state != tgl_sce_committed) {
      memcpy (P->encr_chat.key, P->encr_chat.exchange_key, 256);
      P->encr_chat.key_fingerprint = P->encr_chat.exchange_key_fingerprint;
    }
    break;
  case tgl_sce_aborted:
    P->encr_chat.exchange_state = tgl_sce_none;
    if (P->encr_chat.exchange_state == tgl_sce_committed) {
      memcpy (P->encr_chat.key, P->encr_chat.exchange_key, 256);
      P->encr_chat.key_fingerprint = P->encr_chat.exchange_key_fingerprint;
    }
    break;
  default:
    assert (0);
  }
}
/* }}} */

#define FETCH_COMBINATOR_FUNCTION(NAME) \
  case CODE_ ## NAME:\
    ok = fetch_comb_ ## NAME (TLS, DS_U); \
    break; \


static void replay_log_event (struct tgl_state *TLS) {
  assert (rptr < wptr);
  int op = *rptr;

  vlogprintf (E_DEBUG, "replay_log_event: log_pos=%"_PRINTF_INT64_"d, op=0x%08x\n", binlog_pos, op);

  in_ptr = rptr;
  in_end = wptr;
  if (skip_type_any (TYPE_TO_PARAM (binlog_update)) < 0) {
    vlogprintf (E_ERROR, "Can not replay at %"_PRINTF_INT64_"d (magic = 0x%08x)\n", binlog_pos, *rptr);
    assert (0);
  }
  int *end = in_ptr;
  in_end = in_ptr;
  in_ptr = rptr;
  struct tl_ds_binlog_update *DS_U = fetch_ds_type_binlog_update (TYPE_TO_PARAM (binlog_update));
  assert (in_ptr == end);

  int ok = -1;

  switch (op) {
  FETCH_COMBINATOR_FUNCTION (binlog_start)
  FETCH_COMBINATOR_FUNCTION (binlog_dc_option)
  FETCH_COMBINATOR_FUNCTION (binlog_dc_option_new)
  FETCH_COMBINATOR_FUNCTION (binlog_auth_key)
  FETCH_COMBINATOR_FUNCTION (binlog_default_dc)
  FETCH_COMBINATOR_FUNCTION (binlog_dc_signed)

  FETCH_COMBINATOR_FUNCTION (binlog_our_id)

  FETCH_COMBINATOR_FUNCTION (binlog_set_dh_params)
  FETCH_COMBINATOR_FUNCTION (binlog_set_pts)
  FETCH_COMBINATOR_FUNCTION (binlog_set_qts)
  FETCH_COMBINATOR_FUNCTION (binlog_set_date)
  FETCH_COMBINATOR_FUNCTION (binlog_set_seq)

  struct tgl_user *U = (void *)_U;
  if (flags == TGL_FLAGS_UNCHANGED) { flags = U->flags; }
  flags &= TGLUF_TYPE_MASK;
  
  if ((flags & TGLUF_TYPE_MASK) != (U->flags & TGLUF_TYPE_MASK)) {
    updates |= TGL_UPDATE_FLAGS;
  }
  U->flags = (U->flags & ~TGLUF_TYPE_MASK) | flags;

  if (access_hash && *access_hash != U->access_hash) {
    U->access_hash = *access_hash;
    U->id.access_hash = *access_hash;
    updates |= TGL_UPDATE_ACCESS_HASH;
  }

  if (first_name || last_name) {
    if (!U->first_name || !U->last_name || mystreq1 (U->first_name, first_name, first_name_len) || mystreq1 (U->last_name, last_name, last_name_len)) {
      if (U->first_name) {
        tfree_str (U->first_name);
      }
      U->first_name = tstrndup (first_name, first_name_len);
      if (U->last_name) {
        tfree_str (U->last_name);
      }
      U->last_name = tstrndup (last_name, last_name_len);
    
      updates |= TGL_UPDATE_NAME;

      if (U->print_name) { 
        tglp_peer_delete_name (TLS, (void *)U);
        tfree_str (U->print_name); 
      }
      U->print_name = TLS->callback.create_print_name (TLS, U->id, U->first_name, U->last_name, 0, 0);
      tglp_peer_insert_name (TLS, (void *)U);
    }
  }

  FETCH_COMBINATOR_FUNCTION (binlog_encr_chat_exchange_new)

  FETCH_COMBINATOR_FUNCTION (binlog_msg_update)
  FETCH_COMBINATOR_FUNCTION (binlog_reset_authorization)
  default:
    vlogprintf (E_ERROR, "Unknown op 0x%08x\n", op);
    assert (0);
  }

  if (username && (!U->username || mystreq1 (U->username, username, username_len))) {
    if (U->username) {
      tfree_str (U->username);
    }
    U->username = tstrndup (username, username_len);
    updates |= TGL_UPDATE_USERNAME;
  }

  if (photo) {
    if (!U->photo || U->photo->id != DS_LVAL (photo->id)) {
      if (U->photo) {
        tgls_free_photo (TLS, U->photo);
      }
      U->photo = tglf_fetch_alloc_photo (TLS, photo);
      U->flags |= TGLUF_HAS_PHOTO;
    }
  }
  
#if defined(_MSC_VER) && _MSC_VER >= 1400
  int fd = 0;
  if(_sopen_s (&fd, TLS->binlog_name, _O_WRONLY | _O_EXCL | _O_CREAT, _SH_DENYNO, _S_IREAD | _S_IWRITE) != 0 ) {
#else
  int fd = open (TLS->binlog_name, O_WRONLY | O_EXCL | O_CREAT, 0600);
  if (fd < 0) {
#endif
    perror ("Write new binlog");
    exit (2);
  }

void tgl_replay_log (struct tgl_state *TLS) {
  if (!TLS->binlog_enabled) { return; }
#if defined(WIN32) || defined(_WIN32)
  if (INVALID_FILE_ATTRIBUTES == GetFileAttributesA (TLS->binlog_name) && GetLastError () == ERROR_FILE_NOT_FOUND) {
#else
  if (access (TLS->binlog_name, F_OK) < 0) {
#endif
    printf ("No binlog found. Creating new one\n");
    create_new_binlog (TLS);
  }
#if defined(_MSC_VER) && _MSC_VER >= 1400
  int fd = 0;
  if (_sopen_s(&fd, TLS->binlog_name, _O_RDONLY | _O_BINARY, _SH_DENYNO, _S_IREAD | _S_IWRITE) != 0) {
#elif defined(WIN32) || defined(_WIN32)
  int fd = open (TLS->binlog_name, O_RDONLY | O_BINARY);
  if (fd < 0) {
#else
  int fd = open (TLS->binlog_name, O_RDONLY);
  if (fd < 0) {
#endif
    perror ("binlog open");
    exit (2);
  }
  int end = 0;
  in_replay_log = 1;
  while (1) {
    if (!end && wptr - rptr < MAX_LOG_EVENT_SIZE / 4) {
      if (wptr == rptr) {
        wptr = rptr = binlog_buffer;
      } else {
        int x = wptr - rptr;
        memcpy (binlog_buffer, rptr, 4 * x);
        wptr -= (rptr - binlog_buffer);
        rptr = binlog_buffer;
      }
      int l = (binlog_buffer + BINLOG_BUFFER_SIZE - wptr) * 4;
      ssize_t k = read (fd, wptr, l);
      if (k < 0) {
        perror ("read binlog");
        exit (2);
      }
      assert (!(k & 3));
      if (k < l) {
        end = 1;
      }
      U->bot_info = tglf_fetch_alloc_bot_info (TLS, bot_info);
    }
  }
  in_replay_log = 0;
  close (fd);
}

//static int b_packet_buffer[PACKET_BUFFER_SIZE];

void tgl_reopen_binlog_for_writing (struct tgl_state *TLS) {
#if defined(_MSC_VER) && _MSC_VER >= 1400
  if (_sopen_s (&TLS->binlog_fd, TLS->binlog_name, _O_WRONLY | _O_BINARY, _SH_DENYNO, _S_IREAD | _S_IWRITE) != 0) {
#elif defined(WIN32) || defined(_WIN32)
  TLS->binlog_fd = open (TLS->binlog_name, O_WRONLY | _O_BINARY);
  if (TLS->binlog_fd < 0) {
#else
  TLS->binlog_fd = open (TLS->binlog_name, O_WRONLY);
  if (TLS->binlog_fd < 0) {
#endif
    perror ("binlog open");
    exit (2);
  }

  assert (lseek (TLS->binlog_fd, binlog_pos, SEEK_SET) == binlog_pos);
#if defined(WIN32) || defined(_WIN32)
  HANDLE h = INVALID_HANDLE_VALUE;
  DWORD size_lower, size_upper;
  DWORD err = 0;
  OVERLAPPED ovlp;
  int flags = 0;

  h = (HANDLE)_get_osfhandle(TLS->binlog_fd);
  if (h == INVALID_HANDLE_VALUE) {
    errno = EBADF;
    goto error;
  }

  size_lower = GetFileSize (h, &size_upper);
  if (size_lower == INVALID_FILE_SIZE) {
    goto get_err;
  }

  memset (&ovlp, 0, sizeof ovlp);
  flags |= LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY;

  if (!LockFileEx (h, flags, 0, size_lower, size_upper, &ovlp)) {
    goto get_err;
  }
  return;

error:
  perror ("get lock");
  exit(2);

get_err:
  err = GetLastError();
  switch (err)
  {
  case ERROR_LOCK_VIOLATION:
	  errno = EAGAIN;
	  break;
  case ERROR_NOT_ENOUGH_MEMORY:
	  errno = ENOMEM;
	  break;
  case ERROR_BAD_COMMAND:
	  errno = EINVAL;
	  break;
  default:
	  errno = err;
  }
  goto error;
#else
  if (flock (TLS->binlog_fd, LOCK_EX | LOCK_NB) < 0) {
    perror ("get lock");
    exit (2);
  } 
#endif
}

static void add_log_event (struct tgl_state *TLS, const int *data, int len) {
  vlogprintf (E_DEBUG, "Add log event: magic = 0x%08x, len = %d\n", data[0], len);
  assert (!(len & 3));
  int *ev = talloc (len);
  memcpy (ev, data, len);
  rptr = (void *)ev;
  wptr = rptr + (len / 4);
  int *in = in_ptr;
  int *end = in_end;
  replay_log_event (TLS);
  if (rptr != wptr) {
    vlogprintf (E_ERROR, "Unread %"_PRINTF_INT64_"d ints. Len = %d\n", (long long)(wptr - rptr), len);
    assert (rptr == wptr);
  }
  if (TLS->binlog_enabled) {
    assert (TLS->binlog_fd > 0);
    if (write(TLS->binlog_fd, ev, len) != len)
    {
#ifdef _MSC_VER
#pragma warning(disable: 4996)
#endif
        vlogprintf(E_ERROR, "Could not write to binlog: %s\n", strerror(errno));
        assert(0);
    }
  }
  tfree (ev, len);
  in_ptr = in;
  in_end = end;
}

void bl_do_dc_option_new (struct tgl_state *TLS, int flags, int id, const char *name, int l1, const char *ip, int l2, int port) {
  struct tgl_dc *DC = TLS->DC_list[id];

  if (DC) {
    struct tgl_dc_option *O = DC->options[flags & 3];
    while (O) {
      if (!strncmp (O->ip, ip, l2)) {
        return;
      }
      O = O->next;
    }
  }

  clear_packet ();
  out_int (CODE_binlog_dc_option_new);
  out_int (flags);
  out_int (id);

  out_cstring (name, l1);
  out_cstring (ip, l2);
  out_int (port);

  add_log_event (TLS, packet_buffer, 4 * (packet_ptr - packet_buffer));
}

void bl_do_dc_option (struct tgl_state *TLS, int id, const char *name, int l1, const char *ip, int l2, int port) {
  bl_do_dc_option_new (TLS, 0, id, name, l1, ip, l2, port);
}

void bl_do_set_working_dc (struct tgl_state *TLS, int num) {
  int *ev = alloc_log_event (8);
  ev[0] = CODE_binlog_default_dc;
  ev[1] = num;
  add_log_event (TLS, ev, 8);
}

void bl_do_dc_signed (struct tgl_state *TLS, int id) {
  clear_packet ();
  out_int (CODE_binlog_dc_signed);
  out_int (id);
  add_log_event (TLS, packet_buffer, 4 * (packet_ptr - packet_buffer));
}

void bl_do_set_our_id (struct tgl_state *TLS, int id) {
  if (TLS->our_id) {
    assert (TLS->our_id == id);
    return;
  }

  clear_packet ();
  out_int (CODE_binlog_our_id);
  out_int (id);
  add_log_event (TLS, packet_buffer, 4 * (packet_ptr - packet_buffer));
}

void bl_do_set_dh_params (struct tgl_state *TLS, int root, unsigned char prime[], int version) {
  clear_packet ();
  out_int (CODE_binlog_set_dh_params);
  out_int (root);
  out_ints ((void *)prime, 64);
  out_int (version);
  add_log_event (TLS, packet_buffer, 4 * (packet_ptr - packet_buffer));
}

void bl_do_set_pts (struct tgl_state *TLS, int pts) {
  if (TLS->locks & TGL_LOCK_DIFF) { return; }
  if (pts <= TLS->pts) { return; }

  clear_packet ();
  out_int (CODE_binlog_set_pts);
  out_int (pts);
  add_log_event (TLS, packet_buffer, 4 * (packet_ptr - packet_buffer));
}

void bl_do_set_qts (struct tgl_state *TLS, int qts) {
  if (TLS->locks & TGL_LOCK_DIFF) { return; }
  if (qts <= TLS->qts) { return; }

  clear_packet ();
  out_int (CODE_binlog_set_qts);
  out_int (qts);
  add_log_event (TLS, packet_buffer, 4 * (packet_ptr - packet_buffer));
}

void bl_do_set_date (struct tgl_state *TLS, int date) {
  if (TLS->locks & TGL_LOCK_DIFF) { return; }
  if (date <= TLS->date) { return; }

  clear_packet ();
  out_int (CODE_binlog_set_date);
  out_int (date);
  add_log_event (TLS, packet_buffer, 4 * (packet_ptr - packet_buffer));
}

void bl_do_set_seq (struct tgl_state *TLS, int seq) {
  if (TLS->locks & TGL_LOCK_DIFF) { return; }
  if (seq <= TLS->seq) { return; }

  clear_packet ();
  out_int (CODE_binlog_set_seq);
  out_int (seq);
  add_log_event (TLS, packet_buffer, 4 * (packet_ptr - packet_buffer));
}

void bl_do_set_msg_id (struct tgl_state *TLS, struct tgl_message *M, int id) {
  if (M->id == id) { return; }

  clear_packet ();
  out_int (CODE_binlog_set_msg_id);
  out_long (M->id);
  out_int (id);
  add_log_event (TLS, packet_buffer, 4 * (packet_ptr - packet_buffer));
}

void bl_do_user_delete (struct tgl_state *TLS, struct tgl_user *U) {
  if (U->flags & TGLUF_DELETED) { return; }

  clear_packet ();
  out_int (CODE_binlog_user_delete);
  out_int (tgl_get_peer_id (U->id));
  add_log_event (TLS, packet_buffer, 4 * (packet_ptr - packet_buffer));
}

void bl_do_encr_chat_delete (struct tgl_state *TLS, struct tgl_secret_chat *U) {
  if (!(U->flags & TGLPF_CREATED) || U->state == sc_deleted || U->state == sc_none) { return; }

  clear_packet ();
  out_int (CODE_binlog_encr_chat_delete);
  out_int (tgl_get_peer_id (U->id));
  add_log_event (TLS, packet_buffer, 4 * (packet_ptr - packet_buffer));
}

void bl_do_chat_add_user (struct tgl_state *TLS, struct tgl_chat *C, int version, int user, int inviter, int date) {
  if (C->user_list_version >= version || !C->user_list_version) { return; }

  clear_packet ();
  out_int (CODE_binlog_chat_add_participant);
  out_int (tgl_get_peer_id (C->id));
  out_int (version);
  out_int (user);
  out_int (inviter);
  out_int (date);
  add_log_event (TLS, packet_buffer, 4 * (packet_ptr - packet_buffer));
}

void bl_do_chat_del_user (struct tgl_state *TLS, struct tgl_chat *C, int version, int user) {
  if (C->user_list_version >= version || !C->user_list_version) { return; }

  clear_packet ();
  out_int (CODE_binlog_chat_del_participant);
  out_int (tgl_get_peer_id (C->id));
  out_int (version);
  out_int (user);
  add_log_event (TLS, packet_buffer, 4 * (packet_ptr - packet_buffer));
}
/* }}} */

void bl_do_chat (struct tgl_state *TLS, int id, const char *title, int title_len, int *user_num, int *date, int *version, struct tl_ds_vector *participants, struct tl_ds_chat_photo *chat_photo, struct tl_ds_photo *photo, int *admin, int *last_read_in, int *last_read_out, int flags) /* {{{ */ {
  tgl_peer_t *_U = tgl_peer_get (TLS, TGL_MK_CHAT (id));

  unsigned updates = 0;

  out_long (id);

  if (from_id) {
    assert (to_type);
    assert (to_id);
    (*flags_p) |= (1 << 17);
    out_int (*from_id);
    out_int (*to_type);
    out_int (*to_id);
  }

  if (fwd_from_id) {
    assert (fwd_date);
    (*flags_p) |= (1 << 18);
    out_int (*fwd_from_id);
    out_int (*fwd_date);
  }

  if (date) {
    (*flags_p) |= (1 << 19);
    out_int (*date);
  }

  if (message) {
    (*flags_p) |= (1 << 20);
    out_cstring (message, message_len);
  }

  if (media) {
    (*flags_p) |= (1 << 21);
    store_ds_type_message_media (media, TYPE_TO_PARAM (message_media));
  }
  C->flags = (C->flags & ~TGLCF_TYPE_MASK) | flags;

  if (title && (!C->title || mystreq1 (C->title, title, title_len))) {
    if (C->title) {
      tfree_str (C->title);
    }
    C->title = tstrndup (title, title_len);

    if (C->print_title) { 
      tglp_peer_delete_name (TLS, (void *)C);
      tfree_str (C->print_title); 
    }
    C->print_title = TLS->callback.create_print_name (TLS, C->id, C->title, 0, 0, 0);
    tglp_peer_insert_name (TLS, (void *)C);
    
    updates |= TGL_UPDATE_TITLE;
  }
}

void bl_do_user_set_name (struct tgl_state *TLS, struct tgl_user *U, const char *f, int fl, const char *l, int ll) {
  if ((U->first_name && tstrlen (U->first_name) == fl && !strncmp (U->first_name, f, fl)) &&
      (U->last_name  && tstrlen (U->last_name)  == ll && !strncmp (U->last_name,  l, ll))) {
    return;
  }
  clear_packet ();
  out_int (CODE_binlog_user_set_name);
  out_int (tgl_get_peer_id (U->id));
  out_cstring (f, fl);
  out_cstring (l, ll);
  add_log_event (TLS, packet_buffer, 4 * (packet_ptr - packet_buffer));
}

void bl_do_user_set_username (struct tgl_state *TLS, struct tgl_user *U, const char *f, int l) {
  if ((U->username && tstrlen (U->username) == l && !strncmp (U->username, f, l)) ||
      (!l && !U->username)) {
    return;
  }

void bl_do_user_set_access_hash (struct tgl_state *TLS, struct tgl_user *U, long long access_token) {
  if (U->access_hash == access_token) { return; }
  int *ev = alloc_log_event (16);
  ev[0] = CODE_binlog_user_set_access_hash;
  ev[1] = tgl_get_peer_id (U->id);
  *(long long *)(ev + 2) = access_token;
  add_log_event (TLS, ev, 16);
}

void bl_do_user_set_phone (struct tgl_state *TLS, struct tgl_user *U, const char *p, int pl) {
  if (U->phone && tstrlen (U->phone) == pl && !strncmp (U->phone, p, pl)) {
    return;
  }

  out_long (id);

  if (from_id) {
    assert (to_id);
    assert (to_type);
    (*flags_p) |= (1 << 17);
    out_int (*from_id);
    out_int (*to_type);
    out_int (*to_id);
  }

  if (admin && *admin != C->admin_id) {
    C->admin_id = *admin;
    updates |= TGL_UPDATE_ADMIN;
  }

  if (message) {
    (*flags_p) |= (1 << 20);
    out_cstring (message, message_len);
  }

      if (C->user_list) { tfree (C->user_list, 12 * C->user_list_size); }

      C->user_list_size = DS_LVAL (participants->f1);
      C->user_list = talloc (12 * C->user_list_size);

      int i;
      for (i = 0; i < C->user_list_size; i++) {
        struct tl_ds_chat_participant *DS_P = participants->f2[i];
        C->user_list[i].user_id = DS_LVAL (DS_P->user_id);
        C->user_list[i].inviter_id = DS_LVAL (DS_P->inviter_id);
        C->user_list[i].date = DS_LVAL (DS_P->date);
      }

void bl_do_user_set_real_name (struct tgl_state *TLS, struct tgl_user *U, const char *f, int fl, const char *l, int ll) {
  if ((U->real_first_name && tstrlen (U->real_first_name) == fl && !strncmp (U->real_first_name, f, fl)) &&
      (U->real_last_name  && tstrlen (U->real_last_name)  == ll && !strncmp (U->real_last_name,  l, ll))) {
    return;
  }

  if (file) {
    (*flags_p) |= (1 << 23);
    store_ds_type_encrypted_file (file, TYPE_TO_PARAM (encrypted_file));
  }

void bl_do_chat_set_title (struct tgl_state *TLS, struct tgl_chat *C, const char *s, int l) {
  if (C->title && tstrlen (C->title) == l && !strncmp (C->title, s, l)) { return; }
  clear_packet ();
  out_int (CODE_binlog_chat_set_title);
  out_int (tgl_get_peer_id (C->id));
  out_cstring (s, l);
  add_log_event (TLS, packet_buffer, 4 * (packet_ptr - packet_buffer));
}
/* }}} */

void bl_do_encr_chat (struct tgl_state *TLS, int id, long long *access_hash, int *date, int *admin, int *user_id, void *key, void *g_key, void *first_key_id, int *state, int *ttl, int *layer, int *in_seq_no, int *last_in_seq_no, int *out_seq_no, long long *key_fingerprint, int flags, const char *print_name, int print_name_len) /* {{{ */ {
  tgl_peer_t *_U = tgl_peer_get (TLS, TGL_MK_ENCR_CHAT (id));

  unsigned updates = 0;

void bl_do_encr_chat_exchange_new (struct tgl_state *TLS, struct tgl_secret_chat *E, long long *exchange_id, const void *key, int *state) {
  clear_packet ();

  out_int (CODE_binlog_encr_chat_exchange_new);
  out_int (tgl_get_peer_id (E->id));

  int *flags_p = packet_ptr;
  out_int (0);

  if (exchange_id) {
    *flags_p |= (1 << 17);
    out_long (*exchange_id);
  }
  U->flags = (U->flags & ~TGLECF_TYPE_MASK) | flags;

  if (access_hash && *access_hash != U->access_hash) {
    U->access_hash = *access_hash;
    U->id.access_hash = *access_hash;
    updates |= TGL_UPDATE_ACCESS_HASH;
  }

  if (date) {
    U->date = *date;
  }

  if (admin) {
    U->admin_id = *admin;
  }

  clear_packet ();
  out_int (CODE_binlog_user_new);

  int *flags_p = packet_ptr;

  assert (!(flags & 0xfffe0000));
  out_int (flags);
  out_int (id);

  if (access_hash) {
    if (!P || P->access_hash != *access_hash) {
      out_long (*access_hash);
      (*flags_p) |= (1 << 17);
    }
  }

  if (first_name) {
    if (!P || !P->first_name || !P->last_name || mystreq1 (P->first_name, first_name, first_name_len) || mystreq1 (P->last_name, last_name, last_name_len)) {
      out_cstring (first_name, first_name_len);
      out_cstring (last_name, last_name_len);

      (*flags_p) |= (1 << 18);
    }
  }

  if (key_fingerprint) {
    U->key_fingerprint = *key_fingerprint;
  }

  if (in_seq_no) {
    U->in_seq_no = *in_seq_no;
  }
  if (out_seq_no) {
    U->out_seq_no = *out_seq_no;
  }

  if (real_first_name) {
    assert (real_last_name);
    if (!P || !P->real_first_name || !P->real_last_name || mystreq1 (P->real_first_name, real_first_name, real_first_name_len) || mystreq1 (P->real_last_name, real_last_name, real_last_name_len)) {
      out_cstring (real_first_name, real_first_name_len);
      out_cstring (real_last_name, real_last_name_len);

      (*flags_p) |= (1 << 22);
    }
  }

  tgl_peer_t *Us = tgl_peer_get (TLS, TGL_MK_USER (U->user_id));
  
  if (!U->print_name) {
    if (print_name) {
      U->print_name = tstrndup (print_name, print_name_len);
    } else {
      if (Us) {
        U->print_name = TLS->callback.create_print_name (TLS, TGL_MK_ENCR_CHAT (id), "!", Us->user.first_name, Us->user.last_name, 0);
      } else {
        static char buf[100];
        tsnprintf (buf, 99, "user#%d", U->user_id);
        U->print_name = TLS->callback.create_print_name (TLS, TGL_MK_ENCR_CHAT (id), "!", buf, 0, 0);
      }
      tglp_peer_insert_name (TLS, (void *)U);
    }
  }

  if (g_key) {
    if (!U->g_key)  {
      U->g_key = talloc (256);
    }
    memcpy (U->g_key, g_key, 256);
  }

  if (key) {
    memcpy (U->key, key, 256);
  }

  if (bot_info) {
    if (!P || !P->bot_info || P->bot_info->version != DS_LVAL (bot_info->version)) {
      store_ds_type_bot_info (bot_info, TYPE_TO_PARAM (bot_info));
      (*flags_p) |= (1 << 26);
    }
  }

  if (((*flags_p) & 0xffff0000) || !P || (P->flags & 0xffff) != flags) {
    add_log_event (TLS, packet_buffer, 4 * (packet_ptr - packet_buffer));
  }

void bl_do_set_unread (struct tgl_state *TLS, struct tgl_message *M, int unread) {
  if (M->id != (int)M->id) { bl_do_set_unread_long (TLS, M, unread); }
  if (unread || !M->unread) { return; }
  clear_packet ();
  out_int (CODE_binlog_message_set_unread);
  out_int ((int)M->id);
  add_log_event (TLS, packet_buffer, 4 * (packet_ptr - packet_buffer));
}
/* }}} */

void bl_do_channel (struct tgl_state *TLS, int id, long long *access_hash, int *date, const char *title, int title_len, const char *username, int username_len, struct tl_ds_chat_photo *chat_photo, struct tl_ds_photo *photo, int *version, char *about, int about_len, int *participants_count, int *admins_count, int *kicked_count, int *last_read_in, int flags) /* {{{ */ {
  tgl_peer_t *_U = tgl_peer_get (TLS, TGL_MK_CHANNEL (id));

  unsigned updates = 0;

  clear_packet ();
  out_int (CODE_binlog_chat_new);

  int *flags_p = packet_ptr;

  assert (!(flags & 0xfffe0000));
  out_int (flags);
  out_int (id);

  if (title) {
    if (!P || !P->title || mystreq1 (P->title, title, title_len)) {
      out_cstring (title, title_len);
      (*flags_p) |= (1 << 17);
    }
  }
  C->flags = (C->flags & ~TGLCHF_TYPE_MASK) | flags;

  if (access_hash && *access_hash != C->access_hash) {
    C->access_hash = *access_hash;
    C->id.access_hash = *access_hash;
    updates |= TGL_UPDATE_ACCESS_HASH;
  }

  if (date) {
    C->date = *date;
  }

  if (title && (!C->title || mystreq1 (C->title, title, title_len))) {
    if (C->title) {
      tfree_str (C->title);
    }
    C->title = tstrndup (title, title_len);
    
    if (C->print_title) { 
      tglp_peer_delete_name (TLS, (void *)C);
      tfree_str (C->print_title); 
    }
    C->print_title = TLS->callback.create_print_name (TLS, C->id, C->title, 0, 0, 0);
    tglp_peer_insert_name (TLS, (void *)C);
    
    updates |= TGL_UPDATE_TITLE;
  }
  
  if (chat_photo) {
    if (chat_photo->photo_big && DS_LVAL (chat_photo->photo_big->secret) != C->photo_big.secret) {
      tglf_fetch_file_location (TLS, &C->photo_big, chat_photo->photo_big);
      tglf_fetch_file_location (TLS, &C->photo_small, chat_photo->photo_small);
      updates |= TGL_UPDATE_PHOTO;
    }
  }

  if (photo) {
    if (!C->photo || C->photo->id != DS_LVAL (photo->id)) {
      if (C->photo) {
        tgls_free_photo (TLS, C->photo);
      }
      C->photo = tglf_fetch_alloc_photo (TLS, photo);
      C->flags |= TGLPF_HAS_PHOTO;
    }
  }

  if (username) {
    if (!C->username || mystreq1 (C->username, username, username_len)) {
      if (C->username) {
        tfree_str (C->username);
      }
      C->username = tstrndup (username, username_len);
      updates |= TGL_UPDATE_USERNAME;
    }
  }
  
  if (about) {
    if (!C->about || mystreq1 (C->about, about, about_len)) {
      tfree_str (C->about);
    }
    C->about = tstrndup (about, about_len);
  }

  if (admins_count) {
    C->admins_count = *admins_count;
  }

  if (((*flags_p) & 0xffff0000) || !P || (P->flags & 0xffff) != flags)   {
    add_log_event (TLS, packet_buffer, 4 * (packet_ptr - packet_buffer));
  }
}

void bl_do_encr_chat_new (struct tgl_state *TLS, int id, long long *access_hash, int *date, int *admin, int *user_id, void *key, void *g_key, void *first_key_id, int *state, int *ttl, int *layer, int *in_seq_no, int *last_in_seq_no, int *out_seq_no, long long *key_fingerprint, int flags) {
  tgl_peer_t *PP = tgl_peer_get (TLS, TGL_MK_ENCR_CHAT (id));
  struct tgl_secret_chat *P = PP ? &PP->encr_chat : NULL;

  if (flags == TGL_FLAGS_UNCHANGED) {
    flags = P->flags & 0xffff;
  }

  clear_packet ();
  out_int (CODE_binlog_encr_chat_new);

  int *flags_p = packet_ptr;

  assert (!(flags & 0xfffe0000));
  out_int (flags);
  out_int (id);

  if (access_hash) {
    if (!P || P->access_hash != *access_hash) {
      out_long (*access_hash);
      (*flags_p) |= (1 << 17);
    }
  }

  if (date) {
    if (!P || P->date != *date) {
      out_int (*date);
      (*flags_p) |= (1 << 18);
    }
  }

  if (admin) {
    if (!P || P->admin_id != *admin) {
      out_int (*admin);
      (*flags_p) |= (1 << 19);
    }
  }
  
  if (last_read_in) {
    C->last_read_in = *last_read_in;
    tgls_messages_mark_read (TLS, C->last, 0, C->last_read_in);
  }
  
  if (TLS->callback.channel_update && updates) {
    TLS->callback.channel_update (TLS, C, updates);
  }
}
/* }}} */

void bl_do_peer_delete (struct tgl_state *TLS, tgl_peer_id_t id) /* {{{ */ {
  tgl_peer_t *P = tgl_peer_get (TLS, id);
  if (!P || !(P->flags & TGLPF_CREATED)) { return; }

  if (P->flags & TGLPF_DELETED) { return; }
  P->flags |= TGLPF_DELETED;

  switch (id.peer_type) {
  case TGL_PEER_USER:
    if (TLS->callback.user_update) {
      TLS->callback.user_update (TLS, (void *)P, TGL_UPDATE_DELETED);
    }
    break;
  case TGL_PEER_CHAT:
    if (TLS->callback.chat_update) {
      TLS->callback.chat_update (TLS, (void *)P, TGL_UPDATE_DELETED);
    }
  }

  if (in_seq_no || last_in_seq_no || out_seq_no) {
    if (!P || (in_seq_no && P->in_seq_no != *in_seq_no) ||
              (out_seq_no && P->out_seq_no != *out_seq_no) ||
              (last_in_seq_no && P->last_in_seq_no != *last_in_seq_no)) {

      out_int (in_seq_no ? *in_seq_no : P ? P->in_seq_no : 0);
      out_int (last_in_seq_no ? *last_in_seq_no : P ? P->last_in_seq_no : 0);
      out_int (out_seq_no ? *out_seq_no : P ? P->out_seq_no : 0);
      (*flags_p) |= (1 << 26);
    }
    break;
  case TGL_PEER_CHANNEL:
    if (TLS->callback.channel_update) {
      TLS->callback.channel_update (TLS, (void *)P, TGL_UPDATE_DELETED);
    }
  }

  if (((*flags_p) & 0xffff0000) || !P || (P->flags & 0xffff) != flags)   {
    add_log_event (TLS, packet_buffer, 4 * (packet_ptr - packet_buffer));
  }
}
/* }}} */
