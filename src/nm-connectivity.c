/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2011 Thomas Bechtold <thomasbechtold@jpberlin.de>
 * Copyright (C) 2011 Dan Williams <dcbw@redhat.com>
 */

#include <config.h>

#include <string.h>
#if WITH_CONCHECK
#include <libsoup/soup.h>
#endif

#include "nm-connectivity.h"
#include "nm-logging.h"
#include "nm-manager.h"

G_DEFINE_TYPE (NMConnectivity, nm_connectivity, G_TYPE_OBJECT)

#define NM_CONNECTIVITY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CONNECTIVITY, NMConnectivityPrivate))


#define DEFAULT_RESPONSE "NetworkManager is online" /* NOT LOCALIZED */

typedef struct {
	char *uri;
	char *response;
	guint interval;

#if WITH_CONCHECK
	SoupSession *soup_session;
	gboolean running;
	guint check_id;
#endif

	gboolean connected;
} NMConnectivityPrivate;

enum {
	PROP_0,
	PROP_URI,
	PROP_INTERVAL,
	PROP_RESPONSE,
	PROP_CONNECTED,
	LAST_PROP
};


gboolean
nm_connectivity_get_connected (NMConnectivity *connectivity)
{
	g_return_val_if_fail (NM_IS_CONNECTIVITY (connectivity), FALSE);

	return NM_CONNECTIVITY_GET_PRIVATE (connectivity)->connected;
}

static void
update_connected (NMConnectivity *self, gboolean connected)
{
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);
	gboolean old_connected = priv->connected;

	priv->connected = connected;
	if (priv->connected != old_connected)
		g_object_notify (G_OBJECT (self), NM_CONNECTIVITY_CONNECTED);
}

#if WITH_CONCHECK
static void
nm_connectivity_check_cb (SoupSession *session, SoupMessage *msg, gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	NMConnectivity *self;
	NMConnectivityPrivate *priv;
	gboolean connected_new = FALSE;
	const char *nm_header;

	self = NM_CONNECTIVITY (g_async_result_get_source_object (G_ASYNC_RESULT (simple)));
	g_object_unref (self);
	priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	/* Check headers; if we find the NM-specific one we're done */
	nm_header = soup_message_headers_get_one (msg->response_headers, "X-NetworkManager-Status");
	if (g_strcmp0 (nm_header, "online") == 0) {
		nm_log_dbg (LOGD_CONCHECK, "Connectivity check for uri '%s' with Status header successful.", priv->uri);
		connected_new = TRUE;
	} else if (msg->status_code == SOUP_STATUS_OK) {
		/* check response */
		if (msg->response_body->data &&	(g_str_has_prefix (msg->response_body->data, priv->response))) {
			nm_log_dbg (LOGD_CONCHECK, "Connectivity check for uri '%s' successful.",
			            priv->uri);
			connected_new = TRUE;
		} else {
			nm_log_info (LOGD_CONCHECK, "Connectivity check for uri '%s' did not match expected response '%s'.",
			             priv->uri, priv->response);
		}
	} else {
		nm_log_info (LOGD_CONCHECK, "Connectivity check for uri '%s' returned status '%d %s'.",
		             priv->uri, msg->status_code, msg->reason_phrase);
	}

	g_simple_async_result_set_op_res_gboolean (simple, connected_new);
	g_simple_async_result_complete (simple);

	update_connected (self, connected_new);
}

static void
run_check_complete (GObject      *object,
                    GAsyncResult *result,
                    gpointer      user_data)
{
	NMConnectivity *self = NM_CONNECTIVITY (object);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);
	GError *error = NULL;

	nm_connectivity_check_finish (self, result, &error);
	priv->running = FALSE;
	if (error) {
		nm_log_err (LOGD_CONCHECK, "Connectivity check failed: %s", error->message);
		g_error_free (error);
	}
}

static gboolean
run_check (gpointer user_data)
{
	NMConnectivity *self = NM_CONNECTIVITY (user_data);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	nm_connectivity_check_async (self, run_check_complete, NULL);
	priv->running = TRUE;
	nm_log_dbg (LOGD_CONCHECK, "Connectivity check with uri '%s' started.", priv->uri);

	return TRUE;
}
#endif

void
nm_connectivity_set_online (NMConnectivity *self,
                            gboolean        online)
{
#if WITH_CONCHECK
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	if (online && priv->uri && priv->interval) {
		if (!priv->check_id)
			priv->check_id = g_timeout_add_seconds (priv->interval, run_check, self);
		if (!priv->running)
			run_check (self);

		return;
	} else if (priv->check_id) {
		g_source_remove (priv->check_id);
		priv->check_id = 0;
	}
#endif

	/* Either @online is %TRUE but we aren't checking connectivity, or
	 * @online is %FALSE. Either way we can update our status immediately.
	 */
	update_connected (self, online);
}

void
nm_connectivity_check_async (NMConnectivity      *self,
                             GAsyncReadyCallback  callback,
                             gpointer             user_data)
{
	NMConnectivityPrivate *priv;
#if WITH_CONCHECK
	SoupMessage *msg;
#endif
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (NM_IS_CONNECTIVITY (self), FALSE);
	priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	simple = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                    nm_connectivity_check_async);

#if WITH_CONCHECK
	if (priv->uri && priv->interval) {
		msg = soup_message_new ("GET", priv->uri);
		soup_message_set_flags (msg, SOUP_MESSAGE_NO_REDIRECT);
		soup_session_queue_message (priv->soup_session,
		                            msg,
		                            nm_connectivity_check_cb,
		                            simple);

		return;
	}
#endif

	g_simple_async_result_set_op_res_gboolean (simple, TRUE);
	g_simple_async_result_complete_in_idle (simple);
}

gboolean
nm_connectivity_check_finish (NMConnectivity  *self,
                              GAsyncResult    *result,
                              GError         **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self), nm_connectivity_check_async), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	return g_simple_async_result_get_op_res_gboolean (simple);
}


NMConnectivity *
nm_connectivity_new (const gchar *check_uri,
                     guint check_interval,
                     const gchar *check_response)
{
	NMConnectivity *self;

	self = g_object_new (NM_TYPE_CONNECTIVITY,
	                     NM_CONNECTIVITY_URI, check_uri,
	                     NM_CONNECTIVITY_INTERVAL, check_interval,
	                     NM_CONNECTIVITY_RESPONSE, check_response ? check_response : DEFAULT_RESPONSE,
	                     NULL);
	g_return_val_if_fail (self != NULL, NULL);
	update_connected (self, FALSE);

	return self;
}

static char *
get_non_empty_string_value (const GValue *val)
{
	const char *s;

	s = g_value_get_string (val);
	if (s && s[0])
		return g_strdup (s);
	else
		return NULL;
}

static void
set_property (GObject *object, guint property_id,
              const GValue *value, GParamSpec *pspec)
{
	NMConnectivity *self = NM_CONNECTIVITY (object);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	switch (property_id) {
	case PROP_URI:
		g_free (priv->uri);
		priv->uri = get_non_empty_string_value (value);

#if WITH_CONCHECK
		if (priv->uri) {
			SoupURI *uri = soup_uri_new (priv->uri);

			if (!uri || !SOUP_URI_VALID_FOR_HTTP (uri)) {
				nm_log_err (LOGD_CONCHECK, "Invalid uri '%s' for connectivity check.", priv->uri);
				g_free (priv->uri);
				priv->uri = NULL;
			}
		}
#endif
		break;
	case PROP_INTERVAL:
		priv->interval = g_value_get_uint (value);
		break;
	case PROP_RESPONSE:
		g_free (priv->response);
		priv->response = get_non_empty_string_value (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint property_id,
              GValue *value, GParamSpec *pspec)
{
	NMConnectivity *self = NM_CONNECTIVITY (object);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	switch (property_id) {
	case PROP_URI:
		g_value_set_string (value, priv->uri);
		break;
	case PROP_INTERVAL:
		g_value_set_uint (value, priv->interval);
		break;
	case PROP_RESPONSE:
		g_value_set_string (value, priv->response);
		break;
	case PROP_CONNECTED:
		g_value_set_boolean (value, priv->connected);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
		break;
	}
}


static void
nm_connectivity_init (NMConnectivity *self)
{
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

#if WITH_CONCHECK
	priv->soup_session = soup_session_async_new_with_options (SOUP_SESSION_TIMEOUT, 15, NULL);
#endif
}


static void
dispose (GObject *object)
{
	NMConnectivity *self = NM_CONNECTIVITY (object);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	g_free (priv->uri);
	g_free (priv->response);

#if WITH_CONCHECK
	if (priv->soup_session) {
		soup_session_abort (priv->soup_session);
		g_clear_object (&priv->soup_session);
	}

	if (priv->check_id > 0) {
		g_source_remove (priv->check_id);
		priv->check_id = 0;
	}
#endif
}


static void
nm_connectivity_class_init (NMConnectivityClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	g_type_class_add_private (klass, sizeof (NMConnectivityPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_URI,
		 g_param_spec_string (NM_CONNECTIVITY_URI,
		                      "URI",
		                      "Connectivity check URI",
		                      NULL,
		                      G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_INTERVAL,
		 g_param_spec_uint (NM_CONNECTIVITY_INTERVAL,
		                    "Interval",
		                    "Connectivity check interval in seconds",
		                    0, G_MAXUINT, 300,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT));

	g_object_class_install_property
		(object_class, PROP_RESPONSE,
		 g_param_spec_string (NM_CONNECTIVITY_RESPONSE,
		                      "Response",
		                      "Expected connectivity check reponse",
		                      DEFAULT_RESPONSE,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT));

	g_object_class_install_property
		(object_class, PROP_CONNECTED,
		 g_param_spec_boolean (NM_CONNECTIVITY_CONNECTED,
		                       "Connected",
		                       "Is connected",
		                       FALSE,
		                       G_PARAM_READABLE));
}

