// SPDX-License-Identifier: MPL-2.0
// Shared between wa_client.c and wa_message.c; not part of the public API.
#pragma once
#include "wa.h"

void wa__log(wa_client *c, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void wa__emit(wa_client *c, const wa_event *ev);

// wa_message.c
void wa__on_success(wa_client *c);
// Returns true if the node was handled.
bool wa__handle_message(wa_client *c, const wa_node *n);
bool wa__handle_notification(wa_client *c, const wa_node *n);
bool wa__handle_iq_response(wa_client *c, const wa_node *n);
// <ack class=tag id to=from [participant] [recipient] [type] [error]>
void wa__send_ack(wa_client *c, const wa_node *n, int error);

// wa_send.c
bool wa__send_handle_iq(wa_client *c, const wa_node *n);  // true if it was a send's request
bool wa__handle_ack(wa_client *c, const wa_node *n);
void wa__send_tick(wa_client *c, uint64_t now);
void wa__send_abort(wa_client *c, const char *why);
void wa__lid_learn(wa_client *c, const char *pn, const char *lid);
