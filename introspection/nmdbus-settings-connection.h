/*
 * Generated by gdbus-codegen 2.40.2. DO NOT EDIT.
 *
 * The license of this code is the same as for the source it was derived from.
 */

#ifndef __NMDBUS_SETTINGS_CONNECTION_H__
#define __NMDBUS_SETTINGS_CONNECTION_H__

#include <gio/gio.h>

G_BEGIN_DECLS


/* ------------------------------------------------------------------------ */
/* Declarations for org.freedesktop.NetworkManager.Settings.Connection */

#define NMDBUS_TYPE_SETTINGS_CONNECTION (nmdbus_settings_connection_get_type ())
#define NMDBUS_SETTINGS_CONNECTION(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NMDBUS_TYPE_SETTINGS_CONNECTION, NMDBusSettingsConnection))
#define NMDBUS_IS_SETTINGS_CONNECTION(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NMDBUS_TYPE_SETTINGS_CONNECTION))
#define NMDBUS_SETTINGS_CONNECTION_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE ((o), NMDBUS_TYPE_SETTINGS_CONNECTION, NMDBusSettingsConnectionIface))

struct _NMDBusSettingsConnection;
typedef struct _NMDBusSettingsConnection NMDBusSettingsConnection;
typedef struct _NMDBusSettingsConnectionIface NMDBusSettingsConnectionIface;

struct _NMDBusSettingsConnectionIface
{
  GTypeInterface parent_iface;



  gboolean (*handle_clear_secrets) (
    NMDBusSettingsConnection *object,
    GDBusMethodInvocation *invocation);

  gboolean (*handle_delete) (
    NMDBusSettingsConnection *object,
    GDBusMethodInvocation *invocation);

  gboolean (*handle_get_secrets) (
    NMDBusSettingsConnection *object,
    GDBusMethodInvocation *invocation,
    const gchar *arg_setting_name);

  gboolean (*handle_get_settings) (
    NMDBusSettingsConnection *object,
    GDBusMethodInvocation *invocation);

  gboolean (*handle_save) (
    NMDBusSettingsConnection *object,
    GDBusMethodInvocation *invocation);

  gboolean (*handle_update) (
    NMDBusSettingsConnection *object,
    GDBusMethodInvocation *invocation,
    GVariant *arg_properties);

  gboolean (*handle_update_unsaved) (
    NMDBusSettingsConnection *object,
    GDBusMethodInvocation *invocation,
    GVariant *arg_properties);

  gboolean  (*get_unsaved) (NMDBusSettingsConnection *object);

  void (*properties_changed) (
    NMDBusSettingsConnection *object,
    GVariant *arg_properties);

  void (*removed) (
    NMDBusSettingsConnection *object);

  void (*updated) (
    NMDBusSettingsConnection *object);

};

GType nmdbus_settings_connection_get_type (void) G_GNUC_CONST;

GDBusInterfaceInfo *nmdbus_settings_connection_interface_info (void);
guint nmdbus_settings_connection_override_properties (GObjectClass *klass, guint property_id_begin);


/* D-Bus method call completion functions: */
void nmdbus_settings_connection_complete_update (
    NMDBusSettingsConnection *object,
    GDBusMethodInvocation *invocation);

void nmdbus_settings_connection_complete_update_unsaved (
    NMDBusSettingsConnection *object,
    GDBusMethodInvocation *invocation);

void nmdbus_settings_connection_complete_delete (
    NMDBusSettingsConnection *object,
    GDBusMethodInvocation *invocation);

void nmdbus_settings_connection_complete_get_settings (
    NMDBusSettingsConnection *object,
    GDBusMethodInvocation *invocation,
    GVariant *settings);

void nmdbus_settings_connection_complete_get_secrets (
    NMDBusSettingsConnection *object,
    GDBusMethodInvocation *invocation,
    GVariant *secrets);

void nmdbus_settings_connection_complete_clear_secrets (
    NMDBusSettingsConnection *object,
    GDBusMethodInvocation *invocation);

void nmdbus_settings_connection_complete_save (
    NMDBusSettingsConnection *object,
    GDBusMethodInvocation *invocation);



/* D-Bus signal emissions functions: */
void nmdbus_settings_connection_emit_updated (
    NMDBusSettingsConnection *object);

void nmdbus_settings_connection_emit_removed (
    NMDBusSettingsConnection *object);

void nmdbus_settings_connection_emit_properties_changed (
    NMDBusSettingsConnection *object,
    GVariant *arg_properties);



/* D-Bus method calls: */
void nmdbus_settings_connection_call_update (
    NMDBusSettingsConnection *proxy,
    GVariant *arg_properties,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean nmdbus_settings_connection_call_update_finish (
    NMDBusSettingsConnection *proxy,
    GAsyncResult *res,
    GError **error);

gboolean nmdbus_settings_connection_call_update_sync (
    NMDBusSettingsConnection *proxy,
    GVariant *arg_properties,
    GCancellable *cancellable,
    GError **error);

void nmdbus_settings_connection_call_update_unsaved (
    NMDBusSettingsConnection *proxy,
    GVariant *arg_properties,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean nmdbus_settings_connection_call_update_unsaved_finish (
    NMDBusSettingsConnection *proxy,
    GAsyncResult *res,
    GError **error);

gboolean nmdbus_settings_connection_call_update_unsaved_sync (
    NMDBusSettingsConnection *proxy,
    GVariant *arg_properties,
    GCancellable *cancellable,
    GError **error);

void nmdbus_settings_connection_call_delete (
    NMDBusSettingsConnection *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean nmdbus_settings_connection_call_delete_finish (
    NMDBusSettingsConnection *proxy,
    GAsyncResult *res,
    GError **error);

gboolean nmdbus_settings_connection_call_delete_sync (
    NMDBusSettingsConnection *proxy,
    GCancellable *cancellable,
    GError **error);

void nmdbus_settings_connection_call_get_settings (
    NMDBusSettingsConnection *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean nmdbus_settings_connection_call_get_settings_finish (
    NMDBusSettingsConnection *proxy,
    GVariant **out_settings,
    GAsyncResult *res,
    GError **error);

gboolean nmdbus_settings_connection_call_get_settings_sync (
    NMDBusSettingsConnection *proxy,
    GVariant **out_settings,
    GCancellable *cancellable,
    GError **error);

void nmdbus_settings_connection_call_get_secrets (
    NMDBusSettingsConnection *proxy,
    const gchar *arg_setting_name,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean nmdbus_settings_connection_call_get_secrets_finish (
    NMDBusSettingsConnection *proxy,
    GVariant **out_secrets,
    GAsyncResult *res,
    GError **error);

gboolean nmdbus_settings_connection_call_get_secrets_sync (
    NMDBusSettingsConnection *proxy,
    const gchar *arg_setting_name,
    GVariant **out_secrets,
    GCancellable *cancellable,
    GError **error);

void nmdbus_settings_connection_call_clear_secrets (
    NMDBusSettingsConnection *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean nmdbus_settings_connection_call_clear_secrets_finish (
    NMDBusSettingsConnection *proxy,
    GAsyncResult *res,
    GError **error);

gboolean nmdbus_settings_connection_call_clear_secrets_sync (
    NMDBusSettingsConnection *proxy,
    GCancellable *cancellable,
    GError **error);

void nmdbus_settings_connection_call_save (
    NMDBusSettingsConnection *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean nmdbus_settings_connection_call_save_finish (
    NMDBusSettingsConnection *proxy,
    GAsyncResult *res,
    GError **error);

gboolean nmdbus_settings_connection_call_save_sync (
    NMDBusSettingsConnection *proxy,
    GCancellable *cancellable,
    GError **error);



/* D-Bus property accessors: */
gboolean nmdbus_settings_connection_get_unsaved (NMDBusSettingsConnection *object);
void nmdbus_settings_connection_set_unsaved (NMDBusSettingsConnection *object, gboolean value);


/* ---- */

#define NMDBUS_TYPE_SETTINGS_CONNECTION_PROXY (nmdbus_settings_connection_proxy_get_type ())
#define NMDBUS_SETTINGS_CONNECTION_PROXY(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NMDBUS_TYPE_SETTINGS_CONNECTION_PROXY, NMDBusSettingsConnectionProxy))
#define NMDBUS_SETTINGS_CONNECTION_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), NMDBUS_TYPE_SETTINGS_CONNECTION_PROXY, NMDBusSettingsConnectionProxyClass))
#define NMDBUS_SETTINGS_CONNECTION_PROXY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NMDBUS_TYPE_SETTINGS_CONNECTION_PROXY, NMDBusSettingsConnectionProxyClass))
#define NMDBUS_IS_SETTINGS_CONNECTION_PROXY(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NMDBUS_TYPE_SETTINGS_CONNECTION_PROXY))
#define NMDBUS_IS_SETTINGS_CONNECTION_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), NMDBUS_TYPE_SETTINGS_CONNECTION_PROXY))

typedef struct _NMDBusSettingsConnectionProxy NMDBusSettingsConnectionProxy;
typedef struct _NMDBusSettingsConnectionProxyClass NMDBusSettingsConnectionProxyClass;
typedef struct _NMDBusSettingsConnectionProxyPrivate NMDBusSettingsConnectionProxyPrivate;

struct _NMDBusSettingsConnectionProxy
{
  /*< private >*/
  GDBusProxy parent_instance;
  NMDBusSettingsConnectionProxyPrivate *priv;
};

struct _NMDBusSettingsConnectionProxyClass
{
  GDBusProxyClass parent_class;
};

GType nmdbus_settings_connection_proxy_get_type (void) G_GNUC_CONST;

void nmdbus_settings_connection_proxy_new (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
NMDBusSettingsConnection *nmdbus_settings_connection_proxy_new_finish (
    GAsyncResult        *res,
    GError             **error);
NMDBusSettingsConnection *nmdbus_settings_connection_proxy_new_sync (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);

void nmdbus_settings_connection_proxy_new_for_bus (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
NMDBusSettingsConnection *nmdbus_settings_connection_proxy_new_for_bus_finish (
    GAsyncResult        *res,
    GError             **error);
NMDBusSettingsConnection *nmdbus_settings_connection_proxy_new_for_bus_sync (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);


/* ---- */

#define NMDBUS_TYPE_SETTINGS_CONNECTION_SKELETON (nmdbus_settings_connection_skeleton_get_type ())
#define NMDBUS_SETTINGS_CONNECTION_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NMDBUS_TYPE_SETTINGS_CONNECTION_SKELETON, NMDBusSettingsConnectionSkeleton))
#define NMDBUS_SETTINGS_CONNECTION_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), NMDBUS_TYPE_SETTINGS_CONNECTION_SKELETON, NMDBusSettingsConnectionSkeletonClass))
#define NMDBUS_SETTINGS_CONNECTION_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NMDBUS_TYPE_SETTINGS_CONNECTION_SKELETON, NMDBusSettingsConnectionSkeletonClass))
#define NMDBUS_IS_SETTINGS_CONNECTION_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NMDBUS_TYPE_SETTINGS_CONNECTION_SKELETON))
#define NMDBUS_IS_SETTINGS_CONNECTION_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), NMDBUS_TYPE_SETTINGS_CONNECTION_SKELETON))

typedef struct _NMDBusSettingsConnectionSkeleton NMDBusSettingsConnectionSkeleton;
typedef struct _NMDBusSettingsConnectionSkeletonClass NMDBusSettingsConnectionSkeletonClass;
typedef struct _NMDBusSettingsConnectionSkeletonPrivate NMDBusSettingsConnectionSkeletonPrivate;

struct _NMDBusSettingsConnectionSkeleton
{
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  NMDBusSettingsConnectionSkeletonPrivate *priv;
};

struct _NMDBusSettingsConnectionSkeletonClass
{
  GDBusInterfaceSkeletonClass parent_class;
};

GType nmdbus_settings_connection_skeleton_get_type (void) G_GNUC_CONST;

NMDBusSettingsConnection *nmdbus_settings_connection_skeleton_new (void);


G_END_DECLS

#endif /* __NMDBUS_SETTINGS_CONNECTION_H__ */