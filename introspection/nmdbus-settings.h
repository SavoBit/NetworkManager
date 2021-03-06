/*
 * Generated by gdbus-codegen 2.40.2. DO NOT EDIT.
 *
 * The license of this code is the same as for the source it was derived from.
 */

#ifndef __NMDBUS_SETTINGS_H__
#define __NMDBUS_SETTINGS_H__

#include <gio/gio.h>

G_BEGIN_DECLS


/* ------------------------------------------------------------------------ */
/* Declarations for org.freedesktop.NetworkManager.Settings */

#define NMDBUS_TYPE_SETTINGS (nmdbus_settings_get_type ())
#define NMDBUS_SETTINGS(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NMDBUS_TYPE_SETTINGS, NMDBusSettings))
#define NMDBUS_IS_SETTINGS(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NMDBUS_TYPE_SETTINGS))
#define NMDBUS_SETTINGS_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE ((o), NMDBUS_TYPE_SETTINGS, NMDBusSettingsIface))

struct _NMDBusSettings;
typedef struct _NMDBusSettings NMDBusSettings;
typedef struct _NMDBusSettingsIface NMDBusSettingsIface;

struct _NMDBusSettingsIface
{
  GTypeInterface parent_iface;



  gboolean (*handle_add_connection) (
    NMDBusSettings *object,
    GDBusMethodInvocation *invocation,
    GVariant *arg_connection);

  gboolean (*handle_add_connection_unsaved) (
    NMDBusSettings *object,
    GDBusMethodInvocation *invocation,
    GVariant *arg_connection);

  gboolean (*handle_get_connection_by_uuid) (
    NMDBusSettings *object,
    GDBusMethodInvocation *invocation,
    const gchar *arg_uuid);

  gboolean (*handle_list_connections) (
    NMDBusSettings *object,
    GDBusMethodInvocation *invocation);

  gboolean (*handle_load_connections) (
    NMDBusSettings *object,
    GDBusMethodInvocation *invocation,
    const gchar *const *arg_filenames);

  gboolean (*handle_reload_connections) (
    NMDBusSettings *object,
    GDBusMethodInvocation *invocation);

  gboolean (*handle_save_hostname) (
    NMDBusSettings *object,
    GDBusMethodInvocation *invocation,
    const gchar *arg_hostname);

  gboolean  (*get_can_modify) (NMDBusSettings *object);

  const gchar *const * (*get_connections) (NMDBusSettings *object);

  const gchar * (*get_hostname) (NMDBusSettings *object);

  void (*connection_removed) (
    NMDBusSettings *object,
    const gchar *arg_connection);

  void (*new_connection) (
    NMDBusSettings *object,
    const gchar *arg_connection);

  void (*properties_changed) (
    NMDBusSettings *object,
    GVariant *arg_properties);

};

GType nmdbus_settings_get_type (void) G_GNUC_CONST;

GDBusInterfaceInfo *nmdbus_settings_interface_info (void);
guint nmdbus_settings_override_properties (GObjectClass *klass, guint property_id_begin);


/* D-Bus method call completion functions: */
void nmdbus_settings_complete_list_connections (
    NMDBusSettings *object,
    GDBusMethodInvocation *invocation,
    const gchar *const *connections);

void nmdbus_settings_complete_get_connection_by_uuid (
    NMDBusSettings *object,
    GDBusMethodInvocation *invocation,
    const gchar *connection);

void nmdbus_settings_complete_add_connection (
    NMDBusSettings *object,
    GDBusMethodInvocation *invocation,
    const gchar *path);

void nmdbus_settings_complete_add_connection_unsaved (
    NMDBusSettings *object,
    GDBusMethodInvocation *invocation,
    const gchar *path);

void nmdbus_settings_complete_load_connections (
    NMDBusSettings *object,
    GDBusMethodInvocation *invocation,
    gboolean status,
    const gchar *const *failures);

void nmdbus_settings_complete_reload_connections (
    NMDBusSettings *object,
    GDBusMethodInvocation *invocation,
    gboolean status);

void nmdbus_settings_complete_save_hostname (
    NMDBusSettings *object,
    GDBusMethodInvocation *invocation);



/* D-Bus signal emissions functions: */
void nmdbus_settings_emit_properties_changed (
    NMDBusSettings *object,
    GVariant *arg_properties);

void nmdbus_settings_emit_new_connection (
    NMDBusSettings *object,
    const gchar *arg_connection);

void nmdbus_settings_emit_connection_removed (
    NMDBusSettings *object,
    const gchar *arg_connection);



/* D-Bus method calls: */
void nmdbus_settings_call_list_connections (
    NMDBusSettings *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean nmdbus_settings_call_list_connections_finish (
    NMDBusSettings *proxy,
    gchar ***out_connections,
    GAsyncResult *res,
    GError **error);

gboolean nmdbus_settings_call_list_connections_sync (
    NMDBusSettings *proxy,
    gchar ***out_connections,
    GCancellable *cancellable,
    GError **error);

void nmdbus_settings_call_get_connection_by_uuid (
    NMDBusSettings *proxy,
    const gchar *arg_uuid,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean nmdbus_settings_call_get_connection_by_uuid_finish (
    NMDBusSettings *proxy,
    gchar **out_connection,
    GAsyncResult *res,
    GError **error);

gboolean nmdbus_settings_call_get_connection_by_uuid_sync (
    NMDBusSettings *proxy,
    const gchar *arg_uuid,
    gchar **out_connection,
    GCancellable *cancellable,
    GError **error);

void nmdbus_settings_call_add_connection (
    NMDBusSettings *proxy,
    GVariant *arg_connection,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean nmdbus_settings_call_add_connection_finish (
    NMDBusSettings *proxy,
    gchar **out_path,
    GAsyncResult *res,
    GError **error);

gboolean nmdbus_settings_call_add_connection_sync (
    NMDBusSettings *proxy,
    GVariant *arg_connection,
    gchar **out_path,
    GCancellable *cancellable,
    GError **error);

void nmdbus_settings_call_add_connection_unsaved (
    NMDBusSettings *proxy,
    GVariant *arg_connection,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean nmdbus_settings_call_add_connection_unsaved_finish (
    NMDBusSettings *proxy,
    gchar **out_path,
    GAsyncResult *res,
    GError **error);

gboolean nmdbus_settings_call_add_connection_unsaved_sync (
    NMDBusSettings *proxy,
    GVariant *arg_connection,
    gchar **out_path,
    GCancellable *cancellable,
    GError **error);

void nmdbus_settings_call_load_connections (
    NMDBusSettings *proxy,
    const gchar *const *arg_filenames,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean nmdbus_settings_call_load_connections_finish (
    NMDBusSettings *proxy,
    gboolean *out_status,
    gchar ***out_failures,
    GAsyncResult *res,
    GError **error);

gboolean nmdbus_settings_call_load_connections_sync (
    NMDBusSettings *proxy,
    const gchar *const *arg_filenames,
    gboolean *out_status,
    gchar ***out_failures,
    GCancellable *cancellable,
    GError **error);

void nmdbus_settings_call_reload_connections (
    NMDBusSettings *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean nmdbus_settings_call_reload_connections_finish (
    NMDBusSettings *proxy,
    gboolean *out_status,
    GAsyncResult *res,
    GError **error);

gboolean nmdbus_settings_call_reload_connections_sync (
    NMDBusSettings *proxy,
    gboolean *out_status,
    GCancellable *cancellable,
    GError **error);

void nmdbus_settings_call_save_hostname (
    NMDBusSettings *proxy,
    const gchar *arg_hostname,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean nmdbus_settings_call_save_hostname_finish (
    NMDBusSettings *proxy,
    GAsyncResult *res,
    GError **error);

gboolean nmdbus_settings_call_save_hostname_sync (
    NMDBusSettings *proxy,
    const gchar *arg_hostname,
    GCancellable *cancellable,
    GError **error);



/* D-Bus property accessors: */
const gchar *const *nmdbus_settings_get_connections (NMDBusSettings *object);
gchar **nmdbus_settings_dup_connections (NMDBusSettings *object);
void nmdbus_settings_set_connections (NMDBusSettings *object, const gchar *const *value);

const gchar *nmdbus_settings_get_hostname (NMDBusSettings *object);
gchar *nmdbus_settings_dup_hostname (NMDBusSettings *object);
void nmdbus_settings_set_hostname (NMDBusSettings *object, const gchar *value);

gboolean nmdbus_settings_get_can_modify (NMDBusSettings *object);
void nmdbus_settings_set_can_modify (NMDBusSettings *object, gboolean value);


/* ---- */

#define NMDBUS_TYPE_SETTINGS_PROXY (nmdbus_settings_proxy_get_type ())
#define NMDBUS_SETTINGS_PROXY(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NMDBUS_TYPE_SETTINGS_PROXY, NMDBusSettingsProxy))
#define NMDBUS_SETTINGS_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), NMDBUS_TYPE_SETTINGS_PROXY, NMDBusSettingsProxyClass))
#define NMDBUS_SETTINGS_PROXY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NMDBUS_TYPE_SETTINGS_PROXY, NMDBusSettingsProxyClass))
#define NMDBUS_IS_SETTINGS_PROXY(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NMDBUS_TYPE_SETTINGS_PROXY))
#define NMDBUS_IS_SETTINGS_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), NMDBUS_TYPE_SETTINGS_PROXY))

typedef struct _NMDBusSettingsProxy NMDBusSettingsProxy;
typedef struct _NMDBusSettingsProxyClass NMDBusSettingsProxyClass;
typedef struct _NMDBusSettingsProxyPrivate NMDBusSettingsProxyPrivate;

struct _NMDBusSettingsProxy
{
  /*< private >*/
  GDBusProxy parent_instance;
  NMDBusSettingsProxyPrivate *priv;
};

struct _NMDBusSettingsProxyClass
{
  GDBusProxyClass parent_class;
};

GType nmdbus_settings_proxy_get_type (void) G_GNUC_CONST;

void nmdbus_settings_proxy_new (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
NMDBusSettings *nmdbus_settings_proxy_new_finish (
    GAsyncResult        *res,
    GError             **error);
NMDBusSettings *nmdbus_settings_proxy_new_sync (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);

void nmdbus_settings_proxy_new_for_bus (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
NMDBusSettings *nmdbus_settings_proxy_new_for_bus_finish (
    GAsyncResult        *res,
    GError             **error);
NMDBusSettings *nmdbus_settings_proxy_new_for_bus_sync (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);


/* ---- */

#define NMDBUS_TYPE_SETTINGS_SKELETON (nmdbus_settings_skeleton_get_type ())
#define NMDBUS_SETTINGS_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NMDBUS_TYPE_SETTINGS_SKELETON, NMDBusSettingsSkeleton))
#define NMDBUS_SETTINGS_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), NMDBUS_TYPE_SETTINGS_SKELETON, NMDBusSettingsSkeletonClass))
#define NMDBUS_SETTINGS_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NMDBUS_TYPE_SETTINGS_SKELETON, NMDBusSettingsSkeletonClass))
#define NMDBUS_IS_SETTINGS_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NMDBUS_TYPE_SETTINGS_SKELETON))
#define NMDBUS_IS_SETTINGS_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), NMDBUS_TYPE_SETTINGS_SKELETON))

typedef struct _NMDBusSettingsSkeleton NMDBusSettingsSkeleton;
typedef struct _NMDBusSettingsSkeletonClass NMDBusSettingsSkeletonClass;
typedef struct _NMDBusSettingsSkeletonPrivate NMDBusSettingsSkeletonPrivate;

struct _NMDBusSettingsSkeleton
{
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  NMDBusSettingsSkeletonPrivate *priv;
};

struct _NMDBusSettingsSkeletonClass
{
  GDBusInterfaceSkeletonClass parent_class;
};

GType nmdbus_settings_skeleton_get_type (void) G_GNUC_CONST;

NMDBusSettings *nmdbus_settings_skeleton_new (void);


G_END_DECLS

#endif /* __NMDBUS_SETTINGS_H__ */
