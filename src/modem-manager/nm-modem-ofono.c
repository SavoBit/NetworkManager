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
 * Copyright (C) 2013 Canonical Ltd.
 */

#include "config.h"

#include <string.h>
#include <glib/gi18n.h>

#include "nm-dbus-glib-types.h"
#include "nm-modem-ofono.h"
#include "nm-device.h"
#include "nm-device-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-gsm.h"
#include "nm-modem-types.h"
#include "nm-enum-types.h"
#include "nm-logging.h"
#include "nm-modem.h"
#include "nm-dbus-manager.h"
#include "nm-marshal.h"
#include "NetworkManagerUtils.h"

typedef enum {
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_ANY = 0,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_GPRS,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_EDGE,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_UMTS,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_HSDPA,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_2G_PREFERRED,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_3G_PREFERRED,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_2G_ONLY,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_3G_ONLY,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_HSUPA,
    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_HSPA,

    MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_LAST = MM_MODEM_GSM_NETWORK_DEPRECATED_MODE_HSPA
} MMModemDeprecatedMode;

typedef enum {
    MM_MODEM_GSM_ALLOWED_MODE_ANY          = 0,
    MM_MODEM_GSM_ALLOWED_MODE_2G_PREFERRED = 1,
    MM_MODEM_GSM_ALLOWED_MODE_3G_PREFERRED = 2,
    MM_MODEM_GSM_ALLOWED_MODE_2G_ONLY      = 3,
    MM_MODEM_GSM_ALLOWED_MODE_3G_ONLY      = 4,
    MM_MODEM_GSM_ALLOWED_MODE_4G_PREFERRED = 5,
    MM_MODEM_GSM_ALLOWED_MODE_4G_ONLY      = 6,

    MM_MODEM_GSM_ALLOWED_MODE_LAST = MM_MODEM_GSM_ALLOWED_MODE_4G_ONLY
} MMModemGsmAllowedMode;

typedef enum {
	MM_MODEM_GSM_ALLOWED_AUTH_UNKNOWN  = 0x0000,
    /* bits 0..4 order match Ericsson device bitmap */
    MM_MODEM_GSM_ALLOWED_AUTH_NONE     = 0x0001,
    MM_MODEM_GSM_ALLOWED_AUTH_PAP      = 0x0002,
    MM_MODEM_GSM_ALLOWED_AUTH_CHAP     = 0x0004,
    MM_MODEM_GSM_ALLOWED_AUTH_MSCHAP   = 0x0008,
    MM_MODEM_GSM_ALLOWED_AUTH_MSCHAPV2 = 0x0010,
    MM_MODEM_GSM_ALLOWED_AUTH_EAP      = 0x0020,

    MM_MODEM_GSM_ALLOWED_AUTH_LAST = MM_MODEM_GSM_ALLOWED_AUTH_EAP
} MMModemGsmAllowedAuth;

G_DEFINE_TYPE (NMModemOfono, nm_modem_ofono, NM_TYPE_MODEM)

#define NM_MODEM_OFONO_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MODEM_OFONO, NMModemOfonoPrivate))

typedef struct {
	GHashTable *connect_properties;

	NMDBusManager *dbus_mgr;

	DBusGProxy *modem_proxy;
	DBusGProxy *connman_proxy;
	DBusGProxy *context_proxy;
	DBusGProxy *simmanager_proxy;

	DBusGProxyCall *call;

	GError *property_error;

	guint connman_iface_source;
	guint connman_iface_retries;

	char **interfaces;
	char *context_path;

	gboolean modem_online;
	gboolean gprs_attached;
	gboolean gprs_powered;

	NMIP4Config *ip4_config;

	NMModemState state;
} NMModemOfonoPrivate;

#define NM_OFONO_ERROR (nm_ofono_error_quark ())

static GQuark
nm_ofono_error_quark (void)
{
        static GQuark quark = 0;
        if (!quark)
                quark = g_quark_from_static_string ("nm-ofono-error");
        return quark;
}

static gboolean
ip_string_to_network_address (const gchar *str,
                              guint32 *out)
{
        struct in_addr addr;

        /* IP address */
        if (inet_pton (AF_INET, str, &addr) <= 0)
                return FALSE;

        *out = (guint32)addr.s_addr;
        return TRUE;
}

/* Disconnect stuff */
typedef struct {
        NMModemOfono *self;
        gboolean warn;
} SimpleDisconnectContext;

static void
simple_disconnect_context_free (SimpleDisconnectContext *ctx)
{
        g_object_unref (ctx->self);
        g_slice_free (SimpleDisconnectContext, ctx);
}

static void
disconnect_done (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	SimpleDisconnectContext *ctx = (SimpleDisconnectContext*) user_data;
	NMModemOfono *self = ctx->self;
	GError *error = NULL;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (!dbus_g_proxy_end_call (proxy, call, &error, G_TYPE_INVALID)) {
		if (ctx->warn)
			nm_log_warn (LOGD_MB, "(%s) failed to disconnect modem: %s",
			             nm_modem_get_uid (NM_MODEM (self)),
			             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}

        simple_disconnect_context_free (ctx);

	g_object_set (NM_MODEM (self), NM_MODEM_CONNECTED, FALSE, NULL);
}

static void
disconnect (NMModem *self,
            gboolean warn)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
        SimpleDisconnectContext *ctx;
	GValue value = G_VALUE_INIT;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

        ctx = g_slice_new (SimpleDisconnectContext);
        ctx->self = g_object_ref (self);
        ctx->warn = warn;

	g_value_init (&value, G_TYPE_BOOLEAN);
	g_value_set_boolean (&value, FALSE);

	dbus_g_proxy_begin_call_with_timeout (priv->context_proxy,
	                                      "SetProperty", disconnect_done,
	                                      ctx, NULL, 20000,
	                                      G_TYPE_STRING, "Active",
	                                      G_TYPE_VALUE, &value,
	                                      G_TYPE_INVALID);

}

static void
deactivate (NMModem *_self, NMDevice *device)
{
	/* Chain up parent's */
	NM_MODEM_CLASS (nm_modem_ofono_parent_class)->deactivate (_self, device);
}

DBusGProxy *
get_ofono_proxy (NMModemOfono *self, const char *path, const char *interface)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	DBusGConnection *bus;
	DBusGProxy *proxy;

	bus = nm_dbus_manager_get_connection (priv->dbus_mgr);

	proxy = dbus_g_proxy_new_for_name (bus,
	                                   OFONO_DBUS_SERVICE,
	                                   path,
	                                   interface);

	return proxy;
}

static void ofono_read_contexts (NMModemOfono *self);

static void
update_ofono_enabled (NMModemOfono *self,
                      gboolean new_enabled)
{
	if (nm_modem_get_mm_enabled (NM_MODEM (self)) != new_enabled) {
		g_object_set (self,
		              NM_MODEM_ENABLED, new_enabled,
		              NULL);
		nm_log_info (LOGD_MB, "(%s) marked enabled: %d", nm_modem_get_path (NM_MODEM (self)), new_enabled);
	}

	if (new_enabled)
		ofono_read_contexts (self);
	else
		g_object_set (self, NM_MODEM_CONNECTED, FALSE, NULL);
}

static void
get_ofono_conn_manager_properties_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	GError *error = NULL;
	GHashTable *properties = NULL;
	GValue *value = NULL;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (!dbus_g_proxy_end_call (proxy, call_id, &error,
	                            DBUS_TYPE_G_MAP_OF_VARIANT, &properties,
	                            G_TYPE_INVALID)) {
		nm_log_warn (LOGD_MB, "failed get connection manager properties: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		return;
	}

	value = g_hash_table_lookup (properties, "Attached");
	if (value)
		priv->gprs_attached = g_value_get_boolean (value);
	else
		nm_log_warn (LOGD_MB, "failed get GPRS state: unexpected reply type");
	g_value_unset (value);

	value = g_hash_table_lookup (properties, "Powered");
	if (value)
		priv->gprs_powered = g_value_get_boolean (value);
	else
		nm_log_warn (LOGD_MB, "failed get modem enabled state: unexpected reply type");
	g_value_unset (value);

	update_ofono_enabled (self, priv->gprs_powered && priv->gprs_attached);
}

static void
get_ofono_conn_manager_properties (NMModemOfono *self)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	dbus_g_proxy_begin_call_with_timeout (priv->connman_proxy,
	                                      "GetProperties",
	                                      get_ofono_conn_manager_properties_done,
	                                      self, NULL, 20000,
	                                      G_TYPE_INVALID);
}

static void
ofono_conn_properties_changed (DBusGProxy *proxy,
                               const char *key,
                               GValue *value,
                               gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (g_strcmp0 (key, "Powered") == 0 && G_VALUE_HOLDS_BOOLEAN (value)) {
		priv->gprs_powered = g_value_get_boolean (value);
	}
	else if (g_strcmp0 (key, "Attached") == 0 && G_VALUE_HOLDS_BOOLEAN (value)) {
		priv->gprs_attached = g_value_get_boolean (value);
	}

	update_ofono_enabled (self, priv->gprs_powered && priv->gprs_attached);
}

static void
ofono_read_imsi_contexts_done (DBusGProxy *proxy,
                               DBusGProxyCall *call_id,
                               gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	GError *error = NULL;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (!dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID)) {
		nm_log_warn (LOGD_MB, "failed notify settings plugin of a new context: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		return;
	}
}

static void
ofono_read_contexts (NMModemOfono *self)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	DBusGConnection *bus;
	DBusGProxy *settings_proxy;
	GHashTable *properties;
	GError *error = NULL;
	char *imsi = NULL;

	nm_log_dbg (LOGD_MB, "in %s", __func__);
	nm_log_info (LOGD_MB, "trying to read IMSI contexts from oFono files");

	bus = nm_dbus_manager_get_connection (priv->dbus_mgr);

	dbus_g_proxy_call_with_timeout (priv->simmanager_proxy,
	                                "GetProperties",
	                                20000,
	                                &error,
	                                G_TYPE_INVALID,
	                                DBUS_TYPE_G_MAP_OF_VARIANT, &properties,
	                                G_TYPE_INVALID);

	if (error) {
		nm_log_warn (LOGD_MB, "Could not get SIM properties: %s",
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}

	imsi = g_value_get_string (g_hash_table_lookup (properties, "SubscriberIdentity"));

	settings_proxy = dbus_g_proxy_new_for_name (bus,
	                                            "com.canonical.NMOfono",
	                                            "/com/canonical/NMOfono",
	                                            "com.canonical.NMOfono");

	dbus_g_proxy_begin_call_with_timeout (settings_proxy,
	                                      "ReadImsiContexts", ofono_read_imsi_contexts_done,
	                                      self, NULL, 20000,
	                                      G_TYPE_STRING, imsi,
	                                      G_TYPE_INVALID);
}

static void
ofono_context_added (DBusGProxy *proxy,
                     const char *path,
                     GValue *prop,
                     gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);

	nm_log_dbg (LOGD_MB, "context %s added", path);

	ofono_read_contexts (self);
}

static void
ofono_context_removed (DBusGProxy *proxy, const char *path, gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	nm_log_dbg (LOGD_MB, "context %s removed", path);
}

static void
ofono_properties_changed (DBusGProxy *proxy,
                          const char *key,
                          GValue *value,
                          gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	nm_log_dbg (LOGD_MB, "in %s: %s", __func__, key);

	if (g_strcmp0 (key, "Online") == 0 && G_VALUE_HOLDS_BOOLEAN (value)) {
		priv->modem_online = g_value_get_boolean (value);
	} else if (g_strcmp0 (key, "Interfaces") == 0 && G_VALUE_HOLDS_BOXED (value)) {
		gboolean found_simmanager = FALSE;
		gboolean found_conn_manager = FALSE;
		int i;

		priv->interfaces = (char **) g_value_get_boxed (value);
		nm_log_info (LOGD_MB, "(%s) updated available interfaces", nm_modem_get_path (NM_MODEM (self)));

		for (i = 0; priv->interfaces[i]; i++) {
			if (g_strrstr (priv->interfaces[i], "SimManager"))
				found_simmanager = TRUE;
			if (g_strrstr (priv->interfaces[i], "ConnectionManager"))
				found_conn_manager = TRUE;
		}

		if (found_simmanager) {
			if (!priv->simmanager_proxy) {
				nm_log_info (LOGD_MB, "ofono: found new SimManager interface");
				priv->simmanager_proxy = get_ofono_proxy (self,
				                                          nm_modem_get_path (NM_MODEM (self)),
				                                          OFONO_DBUS_INTERFACE_SIM_MANAGER);
			}
		}
		else {
			if (priv->simmanager_proxy) {
				nm_log_info (LOGD_MB, "ofono: SimManager interface disappeared");
				g_object_unref (priv->simmanager_proxy);
				priv->simmanager_proxy = NULL;
			}
		}

		if (found_conn_manager) {
			if (!priv->connman_proxy) {
				nm_log_info (LOGD_MB, "ofono: found new ConnectionManager interface");
				priv->connman_proxy = get_ofono_proxy (self,
				                                       nm_modem_get_path (NM_MODEM (self)),
				                                       OFONO_DBUS_INTERFACE_CONNECTION_MANAGER);

				if (priv->connman_proxy) {
					get_ofono_conn_manager_properties (self);

					dbus_g_proxy_add_signal (priv->connman_proxy, "PropertyChanged",
				                         	G_TYPE_STRING, G_TYPE_VALUE,
				                         	G_TYPE_INVALID);
					dbus_g_proxy_connect_signal (priv->connman_proxy, "PropertyChanged",
				                             	G_CALLBACK (ofono_conn_properties_changed),
				                             	self,
				                             	NULL);

					dbus_g_proxy_add_signal (priv->connman_proxy, "ContextAdded",
				                         	G_TYPE_STRING, G_TYPE_VALUE,
				                         	G_TYPE_INVALID);
					dbus_g_proxy_connect_signal (priv->connman_proxy, "ContextAdded",
				                             	G_CALLBACK (ofono_context_added),
				                             	self,
				                             	NULL);
					dbus_g_proxy_add_signal (priv->connman_proxy, "ContextRemoved",
				                         	G_TYPE_STRING,
				                         	G_TYPE_INVALID);
					dbus_g_proxy_connect_signal (priv->connman_proxy, "ContextRemoved",
				                             	G_CALLBACK (ofono_context_removed),
				                             	self,
				                             	NULL);
				}
			}
		}
		else {
			if (priv->connman_proxy) {
				nm_log_info (LOGD_MB, "ofono: ConnectionManager interface disappeared");
				g_object_unref (priv->connman_proxy);
				priv->connman_proxy = NULL;

				/* The connection manager proxy disappeared, we should
				 * consider the modem disabled.
				 */
				update_ofono_enabled (self, FALSE);
				priv->gprs_powered = FALSE;
				priv->gprs_attached = FALSE;
			}
		}
	}
}

NMModem *
nm_modem_ofono_new (const char *path)
{
	nm_log_dbg (LOGD_MB, "in %s", __func__);
	g_return_val_if_fail (path != NULL, NULL);

	nm_log_dbg (LOGD_MB, "in %s: path %s", __func__, path);

	return (NMModem *) g_object_new (NM_TYPE_MODEM_OFONO,
	                                 NM_MODEM_PATH, path,
	                                 NM_MODEM_UID, path,
	                                 NM_MODEM_CONTROL_PORT, "ofono", /* mandatory */
	                                 NM_MODEM_IP_METHOD, MM_MODEM_IP_METHOD_STATIC,
	                                 NM_MODEM_ENABLED, FALSE,
	                                 NM_MODEM_CONNECTED, FALSE,
	                                 NULL);
}

static NMDeviceStateReason
translate_mm_error (GError *error)
{
	NMDeviceStateReason reason;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (dbus_g_error_has_name (error, MM_MODEM_CONNECT_ERROR_NO_CARRIER))
		reason = NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER;
	else if (dbus_g_error_has_name (error, MM_MODEM_CONNECT_ERROR_NO_DIALTONE))
		reason = NM_DEVICE_STATE_REASON_MODEM_NO_DIAL_TONE;
	else if (dbus_g_error_has_name (error, MM_MODEM_CONNECT_ERROR_BUSY))
		reason = NM_DEVICE_STATE_REASON_MODEM_BUSY;
	else if (dbus_g_error_has_name (error, MM_MODEM_CONNECT_ERROR_NO_ANSWER))
		reason = NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT;
	else if (dbus_g_error_has_name (error, MM_MODEM_ERROR_NETWORK_NOT_ALLOWED))
		reason = NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED;
	else if (dbus_g_error_has_name (error, MM_MODEM_ERROR_NETWORK_TIMEOUT))
		reason = NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT;
	else if (dbus_g_error_has_name (error, MM_MODEM_ERROR_NO_NETWORK))
		reason = NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING;
	else if (dbus_g_error_has_name (error, MM_MODEM_ERROR_SIM_NOT_INSERTED))
		reason = NM_DEVICE_STATE_REASON_GSM_SIM_NOT_INSERTED;
	else if (dbus_g_error_has_name (error, MM_MODEM_ERROR_SIM_PIN))
		reason = NM_DEVICE_STATE_REASON_GSM_SIM_PIN_REQUIRED;
	else if (dbus_g_error_has_name (error, MM_MODEM_ERROR_SIM_PUK))
		reason = NM_DEVICE_STATE_REASON_GSM_SIM_PUK_REQUIRED;
	else if (dbus_g_error_has_name (error, MM_MODEM_ERROR_SIM_WRONG))
		reason = NM_DEVICE_STATE_REASON_GSM_SIM_WRONG;
	else {
		/* unable to map the ModemManager error to a NM_DEVICE_STATE_REASON */
		nm_log_dbg (LOGD_MB, "unmapped dbus error detected: '%s'", dbus_g_error_get_name (error));
		reason = NM_DEVICE_STATE_REASON_UNKNOWN;
	}

	/* FIXME: We have only GSM error messages here, and we have no idea which
	   activation state failed. Reasons like:
	   NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED,
	   NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED,
	   NM_DEVICE_STATE_REASON_GSM_APN_FAILED,
	   NM_DEVICE_STATE_REASON_GSM_REGISTRATION_FAILED,
	   NM_DEVICE_STATE_REASON_GSM_PIN_CHECK_FAILED
	   are not used.
	*/
	return reason;
}

static void
stage1_prepare_done (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	GError *error = NULL;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	priv->call = NULL;

	if (priv->connect_properties) {
		g_hash_table_destroy (priv->connect_properties);
		priv->connect_properties = NULL;
	}

	if (!dbus_g_proxy_end_call (proxy, call, &error, G_TYPE_INVALID)) {
		nm_log_warn (LOGD_MB, "OFONO connection failed: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");

		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE, translate_mm_error (error));

		g_error_free (error);
	}
}

static void
ofono_context_get_ip_properties (NMModemOfono *self)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	NMIP4Address *addr;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;
	GHashTable *properties, *ip_settings;
	GError *error = NULL;
	GType prop_dict;
	const gchar *address_string, *gateway_string, *netmask_string, *iface;
	const gchar **dns;
	gpointer settings;
	gboolean ret = FALSE;
	guint32 address_network, gateway_network;
	guint i;
	guint prefix = 0;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	prop_dict = dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE);
	dbus_g_proxy_call_with_timeout (priv->context_proxy,
	                                "GetProperties",
	                                20000, &error,
	                                G_TYPE_INVALID,
	                                prop_dict, &properties,
	                                G_TYPE_INVALID);

	if (!error) {
		settings = g_hash_table_lookup (properties, "Settings");
		if (settings && G_VALUE_HOLDS_BOXED (settings)) {
			ip_settings = (GHashTable*) g_value_get_boxed (settings);

			if (nm_modem_get_mm_connected (self) && g_hash_table_size(ip_settings) <= 0) {
				g_signal_emit_by_name (self, NM_MODEM_PPP_FAILED, NM_DEVICE_STATE_REASON_PPP_FAILED);
				return;
			}

			nm_log_info (LOGD_MB, "(%s): IPv4 static configuration:",
			             nm_modem_get_uid (NM_MODEM (self)));

			iface = g_value_get_string (g_hash_table_lookup (ip_settings, "Interface"));
			if (iface)
				g_object_set (self, NM_MODEM_DATA_PORT, iface, NULL);

			if (priv->ip4_config)
				g_object_unref (priv->ip4_config);
			priv->ip4_config = nm_ip4_config_new ();
			addr = nm_ip4_address_new ();

			address_string = g_value_get_string (g_hash_table_lookup (ip_settings, "Address"));
			if (address_string) {
				if (ip_string_to_network_address (address_string, &address_network)) {
					nm_ip4_address_set_address (addr, address_network);
				}
			} else
				goto out;

			gateway_string = g_value_get_string (g_hash_table_lookup (ip_settings, "Gateway"));
			if (gateway_string) {
				if (ip_string_to_network_address (gateway_string, &gateway_network)) {
					nm_ip4_address_set_gateway (addr, gateway_network);
				}
			} else
				goto out;

			/* retrieve netmask and convert to prefix value */
			netmask_string = g_value_get_string (g_hash_table_lookup (ip_settings, "Netmask"));
			if (ip_string_to_network_address (netmask_string, &address_network)) {
				prefix = nm_utils_ip4_netmask_to_prefix (address_network);
				if (prefix > 0)
					nm_ip4_address_set_prefix (addr, prefix);
			} else
				goto out;

			nm_ip4_config_take_address (priv->ip4_config, addr);

			nm_log_info (LOGD_MB, "  address %s/%d", address_string, prefix);

			/* DNS servers */
			dns = (char **) g_value_get_boxed (g_hash_table_lookup (ip_settings, "DomainNameServers"));
			for (i = 0; dns[i]; i++) {
				if (   ip_string_to_network_address (dns[i], &address_network)
			    	&& address_network > 0) {
					nm_ip4_config_add_nameserver (priv->ip4_config, address_network);
					nm_log_info (LOGD_MB, "  DNS %s", dns[i]);
				}
			}

			ret = TRUE;
		}
	}

out:
	if (!ret) {
		if (error) {
			reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
			g_clear_error (&error);
		} else {
			reason = NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE;
		}
	}

	if (!nm_modem_get_mm_connected (self))
		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, ret, reason);
}

static void
context_properties_changed (DBusGProxy *proxy,
                            const char *key,
                            GValue *value,
                            gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	if (g_strcmp0("Settings", key) == 0) {
		ofono_context_get_ip_properties (self);
	}
}

static void
do_context_activate (NMModemOfono *self, char *context_path)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	GValue value = G_VALUE_INIT;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (NM_IS_MODEM_OFONO (self), FALSE);

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	g_value_init (&value, G_TYPE_BOOLEAN);
	g_value_set_boolean (&value, TRUE);

	if (priv->context_proxy)
		g_object_unref (priv->context_proxy);

	priv->context_proxy = get_ofono_proxy (self,
	                                       context_path,
	                                       OFONO_DBUS_INTERFACE_CONNECTION_CONTEXT);

	if (!priv->context_proxy) {
		nm_log_err (LOGD_MB, "could not bring up connection context proxy");
		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE,
		                       NM_DEVICE_STATE_REASON_MODEM_BUSY);
		return;
	}

	if (!priv->gprs_attached) {
		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE,
		                       NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER);
		return;
	}

	if (priv->ip4_config) {
		/* We have an old copy of the settings from a previous activation,
		 * clear it so that we can gate getting the IP config from oFono
		 * on whether or not we have already received them
		 */
		g_object_unref (priv->ip4_config);
		priv->ip4_config = NULL;
	}

	dbus_g_proxy_add_signal (priv->context_proxy, "PropertyChanged",
	                         G_TYPE_STRING, G_TYPE_VALUE,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->context_proxy, "PropertyChanged",
	                             G_CALLBACK (context_properties_changed),
	                             self,
	                             NULL);

	dbus_g_proxy_begin_call_with_timeout (priv->context_proxy,
	                                      "SetProperty", stage1_prepare_done,
	                                      self, NULL, 20000,
	                                      G_TYPE_STRING, "Active",
	                                      G_TYPE_VALUE, &value,
	                                      G_TYPE_INVALID);

}

static void
context_set_property (gpointer key, gpointer value, gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	GValue val = G_VALUE_INIT;

	nm_log_dbg (LOGD_MB, "%s -- setting context prop: %s == %s",
	            __func__,
	            (char*)key,
	            (char*)value);

	g_value_init (&val, G_TYPE_STRING);
	g_value_set_string (&val, (char*)value);

	if (!priv->property_error) {
		dbus_g_proxy_call_with_timeout (priv->context_proxy,
		                                "SetProperty",
		                                20000,
		                                &priv->property_error,
		                                G_TYPE_STRING, (char*)key,
		                                G_TYPE_VALUE, &val,
		                                G_TYPE_INVALID);
	} else {
		nm_log_warn (LOGD_MB, "could not set context property '%s': %s", (char*)key,
		             priv->property_error
		                 && priv->property_error->message
		                 ? priv->property_error->message : "(unknown)");
	}
}

static void
do_context_prepare (NMModemOfono *self, char *context_path)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (NM_IS_MODEM_OFONO (self), FALSE);

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (priv->context_proxy)
		g_object_unref (priv->context_proxy);

	priv->context_proxy = get_ofono_proxy (self,
	                                       context_path,
	                                       OFONO_DBUS_INTERFACE_CONNECTION_CONTEXT);

	if (priv->context_proxy) {
		priv->property_error = NULL;
		g_hash_table_foreach (priv->connect_properties,
		                      context_set_property,
		                      (gpointer) self);
		do_context_activate (self, context_path);
	}
}

static void
create_new_context_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	NMDeviceStateReason reason;
	GError *error = NULL;
	char *context_path = NULL;
	gboolean ret = FALSE;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

        ret = dbus_g_proxy_end_call (proxy,
                                     call_id,
	                             &error,
	                             DBUS_TYPE_G_OBJECT_PATH, &context_path,
	                             G_TYPE_INVALID);

	nm_log_dbg (LOGD_MB, "%s: context path: %s", __func__, context_path);

	if (ret)
                do_context_prepare (self, context_path);
        else {
                nm_log_warn (LOGD_MB, "Ofono modem context creation failed: (%d) %s",
                             error ? error->code : -1,
                             error && error->message ? error->message : "(unknown)");

		//reason = translate_mm_error (error);
		//if (reason == NM_DEVICE_STATE_REASON_UNKNOWN)
			reason = NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED;
		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE, reason);

		g_error_free (error);
        }
}

static void
do_create_new_context (NMModemOfono *self)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	DBusGProxy *proxy;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (NM_IS_MODEM_OFONO (self), FALSE);

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (priv->connman_proxy) {
		dbus_g_proxy_begin_call_with_timeout (priv->connman_proxy,
	                                              "AddContext", create_new_context_done,
	                                              self, NULL, 20000,
	                                              G_TYPE_STRING, "internet",
	                                              G_TYPE_INVALID);
	}
	else {
		nm_log_err (LOGD_MB, "could not bring up connection manager proxy "
		                     "to add a new context");
	}
}

static gboolean
try_create_new_context (NMModemOfono *self)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	GHashTable *properties;
	char **interfaces;
	GError *error = NULL;
	gboolean found = FALSE;
	int i;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	/* Only retry up to 20 times */
	if (priv->connman_iface_retries < 20) {
		dbus_g_proxy_call_with_timeout (priv->modem_proxy,
	                                        "GetProperties",
	                                        250, &error,
	                                        G_TYPE_INVALID,
	                                        DBUS_TYPE_G_MAP_OF_VARIANT, &properties,
	                                        G_TYPE_INVALID);

		if (!error) {
			interfaces = (char **) g_value_get_boxed (g_hash_table_lookup (properties, "Interfaces"));

			for (i = 0; interfaces[i]; i++) {
				nm_log_dbg (LOGD_MB, "%s ?? %s",
				            interfaces[i],
				            OFONO_DBUS_INTERFACE_CONNECTION_MANAGER);
				if (!g_strcmp0 (interfaces[i],
				                OFONO_DBUS_INTERFACE_CONNECTION_MANAGER)) {
					found = TRUE;
					break;
				}
			}
		}
		else {
			nm_log_dbg (LOGD_MB, "failed test for properties: %s",
			            error && error->message ? error->message : "(unknown)");
		}
		priv->connman_iface_retries++;
	}
	else {
		if (priv->connman_iface_source != 0)
			g_source_remove (priv->connman_iface_source);

		priv->connman_iface_source = 0;
		priv->connman_iface_retries = 0;

		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE, 0);

		return FALSE;
	}

	if (found) {
		if (priv->connman_iface_source != 0)
			g_source_remove (priv->connman_iface_source);

		priv->connman_iface_source = 0;
		priv->connman_iface_retries = 0;
		do_create_new_context (self);
	}

	return !found;
}

static void stage1_enable_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data);

/* do_enable() is used as a GSourceFunc, hence the gboolean return */
static gboolean
do_enable (NMModemOfono *self)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	GValue value = G_VALUE_INIT;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (NM_IS_MODEM_OFONO (self), FALSE);

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	g_value_init (&value, G_TYPE_BOOLEAN);
	g_value_set_boolean (&value, TRUE);

	dbus_g_proxy_begin_call_with_timeout (priv->modem_proxy,
	                                      "SetProperty", stage1_enable_done,
	                                      self, NULL, 20000,
	                                      G_TYPE_STRING, "Online",
	                                      G_TYPE_VALUE, &value,
	                                      G_TYPE_INVALID);

	return FALSE;
}

static void
stage1_enable_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	NMDeviceStateReason reason;
	GError *error = NULL;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID)) {
#if 0
		/* Try once every 5 seconds to see if we've got the right interfaces */
		priv->connman_iface_retries = 0;
		priv->connman_iface_source
			= g_timeout_add (500, (GSourceFunc) try_create_new_context, self);
#endif
		if (priv->context_path)
			do_context_activate (self, priv->context_path);
		else {
			reason = NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED;
			g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE, reason);
		}
	} else {
		nm_log_warn (LOGD_MB, "OFONO modem enable failed: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");

		//if (dbus_g_error_has_name (error, MM_MODEM_ERROR_SIM_PIN))
		//	handle_enable_pin_required (self);
		//else {
			/* try to translate the error reason */
			reason = translate_mm_error (error);
			if (reason == NM_DEVICE_STATE_REASON_UNKNOWN)
				reason = NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED;
			g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE, reason);
		//}

		g_error_free (error);
	}
}

static GHashTable *
create_connect_properties (NMConnection *connection)
{
	NMSettingGsm *setting;
	GHashTable *properties;
	const char *str;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	setting = nm_connection_get_setting_gsm (connection);
	properties = g_hash_table_new (g_str_hash, g_str_equal);

	str = nm_setting_gsm_get_apn (setting);
	if (str)
		g_hash_table_insert (properties, "AccessPointName", g_strdup (str));

	str = nm_setting_gsm_get_username (setting);
	if (str)
		g_hash_table_insert (properties, "Username", g_strdup (str));

	str = nm_setting_gsm_get_password (setting);
	if (str)
		g_hash_table_insert (properties, "Password", g_strdup (str));

	return properties;
}

static NMActStageReturn
act_stage1_prepare (NMModem *modem,
                    NMActRequest *req,
                    GPtrArray **out_hints,
                    const char **out_setting_name,
                    NMDeviceStateReason *reason)
{
	NMModemOfono *self = NM_MODEM_OFONO (modem);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	NMConnection *connection;
	const char *context_id;
	char *context_path;
	char **id = NULL;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	context_id = nm_connection_get_id (connection);
	id = g_strsplit (context_id, "/", 0);
	g_assert (id[2]);

	nm_log_dbg (LOGD_MB, " trying %s %s", id[1], id[2]);

	if (priv->context_path)
		g_free (priv->context_path);

	priv->context_path = g_strdup_printf ("%s/%s",
	                                      nm_modem_get_path (modem),
	                                      id[2]);
	g_strfreev (id);

	/* nm_connection_need_secrets() doesn't apply here, so let's just
	 * set the secret name and hints to NULL explicitly.
	 */
	*out_setting_name = NULL;
	*out_hints = NULL;

	if (priv->context_path) {
		gboolean enabled = nm_modem_get_mm_enabled (modem);

		if (priv->connect_properties)
			g_hash_table_destroy (priv->connect_properties);
		priv->connect_properties = create_connect_properties (connection);

		if (enabled) {
#if 0
			priv->connman_iface_retries = 0;
			priv->connman_iface_source
				= g_timeout_add (500, (GSourceFunc) try_create_new_context, self);
#endif
			do_context_activate (self, priv->context_path);
		} else
			do_enable (self);
	} else {
		nm_log_err (LOGD_MB, "could not set context path for connection");
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static NMActStageReturn
static_stage3_ip4_config_start (NMModem *_self,
                                NMActRequest *req,
                                NMDeviceStateReason *reason)
{
	NMModemOfono *self = NM_MODEM_OFONO (_self);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	GError *error = NULL;

	if (priv->ip4_config) {
		g_signal_emit_by_name (self, NM_MODEM_IP4_CONFIG_RESULT, priv->ip4_config, error);
		priv->ip4_config = NULL;
		g_object_set (self, NM_MODEM_CONNECTED, TRUE, NULL);
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	}

	return ret;
}

static gboolean
check_connection_compatible (NMModem *modem,
                             NMConnection *connection,
                             GError **error)
{
	NMSettingConnection *s_con;
	NMSettingGsm *s_gsm;
	const char *id;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_GSM_SETTING_NAME)) {
		g_set_error (error,
		             NM_OFONO_ERROR, NM_OFONO_ERROR_CONNECTION_NOT_OFONO,
		             "The connection was not a oFono connection.");
		return FALSE;
	}

	s_gsm = nm_connection_get_setting_gsm (connection);
	if (!s_gsm) {
		g_set_error (error,
		             NM_OFONO_ERROR, NM_OFONO_ERROR_CONNECTION_INVALID,
		             "The connection was not a valid oFono connection.");
		return FALSE;
	}

	id = nm_connection_get_id (connection);
	if (!g_strrstr (id, "/context")) {
		g_set_error (error,
		             NM_OFONO_ERROR, NM_OFONO_ERROR_CONNECTION_NOT_OFONO,
		             "The connection was not supported by oFono.");
		return FALSE;
	}

	return TRUE;
}

static NMConnection *
get_best_auto_connection (NMModem *_self,
                          GSList *connections,
                          char **specific_object)
{
        NMModemOfono *self = NM_MODEM_OFONO (_self);
        NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
        GSList *iter;

        for (iter = connections; iter; iter = g_slist_next (iter)) {
                NMConnection *connection = NM_CONNECTION (iter->data);
                NMSettingConnection *s_con;

                s_con = nm_connection_get_setting_connection (connection);
                g_assert (s_con);

                if (!nm_setting_connection_get_autoconnect (s_con))
                        continue;

		/* Return the first connection we find that matches the usual
		 * name for oFono connections.
		 */
                if (g_strrstr (nm_setting_connection_get_id (s_con), "/context"))
                        return connection;
	}

	return NULL;
}

static void
get_ofono_properties_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMModem *self = NM_MODEM (user_data);
	GError *error = NULL;
	GHashTable *properties = NULL;
	GValue *value = NULL;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (!dbus_g_proxy_end_call (proxy, call_id, &error,
	                            DBUS_TYPE_G_MAP_OF_VARIANT, &properties,
	                            G_TYPE_INVALID)) {
		nm_log_warn (LOGD_MB, "failed get modem enabled state: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		return;
	}

	value = g_hash_table_lookup (properties, "Online");
	if (value)
		ofono_properties_changed (NULL, "Online", value, self);
	else
		nm_log_warn (LOGD_MB, "failed get modem online state: unexpected reply type");
	g_value_unset (value);

	value = g_hash_table_lookup (properties, "Interfaces");
	if (value)
		ofono_properties_changed (NULL, "Interfaces", value, self);
	else
		nm_log_warn (LOGD_MB, "failed get available oFono interfaces: unexpected reply type");
	g_value_unset (value);
}

static void
query_ofono_properties (NMModemOfono *self)
{
	nm_log_dbg (LOGD_MB, "in %s", __func__);
	dbus_g_proxy_begin_call (NM_MODEM_OFONO_GET_PRIVATE (self)->modem_proxy,
	                         "GetProperties", get_ofono_properties_done,
	                         self, NULL,
	                         G_TYPE_INVALID);
}

static void
set_ofono_enabled (NMModem *self, gboolean enabled)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	GValue value = G_VALUE_INIT;
	gboolean ret;
	GError *error = NULL;

	g_return_if_fail (self != NULL);
	g_return_if_fail (NM_IS_MODEM_OFONO (self));
	g_return_if_fail (priv != NULL);
	g_return_if_fail (priv->connman_proxy != NULL);

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	g_value_init (&value, G_TYPE_BOOLEAN);
	g_value_set_boolean (&value, enabled);

	ret = dbus_g_proxy_call_with_timeout (priv->connman_proxy,
	                                      "SetProperty",
	                                      20000,
	                                      &error,
	                                      G_TYPE_STRING, "Powered",
	                                      G_TYPE_VALUE, &value,
	                                      G_TYPE_INVALID,
	                                      G_TYPE_INVALID);

	if (!ret) {
		nm_log_warn (LOGD_MB, "OFONO modem set enabled failed: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
	}
	else {
		get_ofono_conn_manager_properties (self);
	}
}

static void
nm_modem_ofono_init (NMModemOfono *self)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	priv->dbus_mgr = nm_dbus_manager_get ();

	priv->modem_proxy = NULL;
	priv->connman_proxy = NULL;
	priv->context_proxy = NULL;
	priv->simmanager_proxy = NULL;

	priv->connman_iface_source = 0;
	priv->connman_iface_retries = 0;

	priv->modem_online = FALSE;
	priv->gprs_powered = FALSE;
	priv->gprs_attached = FALSE;

	priv->ip4_config = NULL;
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;
	NMModemOfonoPrivate *priv;
	DBusGConnection *bus;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	object = G_OBJECT_CLASS (nm_modem_ofono_parent_class)->constructor (type, n_construct_params, construct_params);
	if (!object)
		return NULL;

	priv = NM_MODEM_OFONO_GET_PRIVATE (object);
	bus = nm_dbus_manager_get_connection (priv->dbus_mgr);
	priv->modem_proxy = get_ofono_proxy (NM_MODEM_OFONO (object),
	                                     nm_modem_get_path (NM_MODEM (object)),
	                                     OFONO_DBUS_INTERFACE_MODEM);

	dbus_g_object_register_marshaller (_nm_marshal_VOID__STRING_BOXED,
	                                   G_TYPE_NONE,
	                                   G_TYPE_STRING, G_TYPE_VALUE,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->modem_proxy, "PropertyChanged",
	                         G_TYPE_STRING, G_TYPE_VALUE,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->modem_proxy, "PropertyChanged",
	                             G_CALLBACK (ofono_properties_changed),
	                             object,
	                             NULL);

	query_ofono_properties (NM_MODEM_OFONO (object));

	return object;
}

static void
dispose (GObject *object)
{
	NMModemOfono *self = NM_MODEM_OFONO (object);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (priv->connect_properties)
		g_hash_table_destroy (priv->connect_properties);

	if (priv->ip4_config)
		g_object_unref (priv->ip4_config);

	if (priv->modem_proxy)
		g_object_unref (priv->modem_proxy);
	if (priv->connman_proxy)
		g_object_unref (priv->connman_proxy);
	if (priv->context_proxy)
		g_object_unref (priv->context_proxy);

	G_OBJECT_CLASS (nm_modem_ofono_parent_class)->dispose (object);
}

static void
nm_modem_ofono_class_init (NMModemOfonoClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMModemClass *modem_class = NM_MODEM_CLASS (klass);

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	g_type_class_add_private (object_class, sizeof (NMModemOfonoPrivate));

	/* Virtual methods */
	object_class->constructor = constructor;
	object_class->dispose = dispose;

	modem_class->set_mm_enabled = set_ofono_enabled;
        modem_class->disconnect = disconnect;
	//modem_class->deactivate = deactivate;
	//modem_class->get_user_pass = get_user_pass;
	//modem_class->get_setting_name = get_setting_name;
	modem_class->get_best_auto_connection = get_best_auto_connection;
	//modem_class->complete_connection = complete_connection;
	modem_class->check_connection_compatible = check_connection_compatible;
	modem_class->act_stage1_prepare = act_stage1_prepare;
        modem_class->static_stage3_ip4_config_start = static_stage3_ip4_config_start;

	//dbus_g_error_domain_register (NM_OFONO_ERROR, NULL, NM_TYPE_OFONO_ERROR);
}

