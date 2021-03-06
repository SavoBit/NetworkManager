/*
 * Generated by gdbus-codegen 2.40.2. DO NOT EDIT.
 *
 * The license of this code is the same as for the source it was derived from.
 */

#ifndef __NMDBUS_DEVICE_WIMAX_H__
#define __NMDBUS_DEVICE_WIMAX_H__

#include <gio/gio.h>

G_BEGIN_DECLS


/* ------------------------------------------------------------------------ */
/* Declarations for org.freedesktop.NetworkManager.Device.WiMax */

#define NMDBUS_TYPE_DEVICE_WI_MAX (nmdbus_device_wi_max_get_type ())
#define NMDBUS_DEVICE_WI_MAX(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NMDBUS_TYPE_DEVICE_WI_MAX, NMDBusDeviceWiMax))
#define NMDBUS_IS_DEVICE_WI_MAX(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NMDBUS_TYPE_DEVICE_WI_MAX))
#define NMDBUS_DEVICE_WI_MAX_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE ((o), NMDBUS_TYPE_DEVICE_WI_MAX, NMDBusDeviceWiMaxIface))

struct _NMDBusDeviceWiMax;
typedef struct _NMDBusDeviceWiMax NMDBusDeviceWiMax;
typedef struct _NMDBusDeviceWiMaxIface NMDBusDeviceWiMaxIface;

struct _NMDBusDeviceWiMaxIface
{
  GTypeInterface parent_iface;



  gboolean (*handle_get_nsp_list) (
    NMDBusDeviceWiMax *object,
    GDBusMethodInvocation *invocation);

  const gchar * (*get_active_nsp) (NMDBusDeviceWiMax *object);

  const gchar * (*get_bsid) (NMDBusDeviceWiMax *object);

  guint  (*get_center_frequency) (NMDBusDeviceWiMax *object);

  gint  (*get_cinr) (NMDBusDeviceWiMax *object);

  const gchar * (*get_hw_address) (NMDBusDeviceWiMax *object);

  const gchar *const * (*get_nsps) (NMDBusDeviceWiMax *object);

  gint  (*get_rssi) (NMDBusDeviceWiMax *object);

  gint  (*get_tx_power) (NMDBusDeviceWiMax *object);

  void (*nsp_added) (
    NMDBusDeviceWiMax *object,
    const gchar *arg_nsp);

  void (*nsp_removed) (
    NMDBusDeviceWiMax *object,
    const gchar *arg_nsp);

  void (*properties_changed) (
    NMDBusDeviceWiMax *object,
    GVariant *arg_properties);

};

GType nmdbus_device_wi_max_get_type (void) G_GNUC_CONST;

GDBusInterfaceInfo *nmdbus_device_wi_max_interface_info (void);
guint nmdbus_device_wi_max_override_properties (GObjectClass *klass, guint property_id_begin);


/* D-Bus method call completion functions: */
void nmdbus_device_wi_max_complete_get_nsp_list (
    NMDBusDeviceWiMax *object,
    GDBusMethodInvocation *invocation,
    const gchar *const *nsps);



/* D-Bus signal emissions functions: */
void nmdbus_device_wi_max_emit_properties_changed (
    NMDBusDeviceWiMax *object,
    GVariant *arg_properties);

void nmdbus_device_wi_max_emit_nsp_added (
    NMDBusDeviceWiMax *object,
    const gchar *arg_nsp);

void nmdbus_device_wi_max_emit_nsp_removed (
    NMDBusDeviceWiMax *object,
    const gchar *arg_nsp);



/* D-Bus method calls: */
void nmdbus_device_wi_max_call_get_nsp_list (
    NMDBusDeviceWiMax *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean nmdbus_device_wi_max_call_get_nsp_list_finish (
    NMDBusDeviceWiMax *proxy,
    gchar ***out_nsps,
    GAsyncResult *res,
    GError **error);

gboolean nmdbus_device_wi_max_call_get_nsp_list_sync (
    NMDBusDeviceWiMax *proxy,
    gchar ***out_nsps,
    GCancellable *cancellable,
    GError **error);



/* D-Bus property accessors: */
const gchar *const *nmdbus_device_wi_max_get_nsps (NMDBusDeviceWiMax *object);
gchar **nmdbus_device_wi_max_dup_nsps (NMDBusDeviceWiMax *object);
void nmdbus_device_wi_max_set_nsps (NMDBusDeviceWiMax *object, const gchar *const *value);

const gchar *nmdbus_device_wi_max_get_hw_address (NMDBusDeviceWiMax *object);
gchar *nmdbus_device_wi_max_dup_hw_address (NMDBusDeviceWiMax *object);
void nmdbus_device_wi_max_set_hw_address (NMDBusDeviceWiMax *object, const gchar *value);

guint nmdbus_device_wi_max_get_center_frequency (NMDBusDeviceWiMax *object);
void nmdbus_device_wi_max_set_center_frequency (NMDBusDeviceWiMax *object, guint value);

gint nmdbus_device_wi_max_get_rssi (NMDBusDeviceWiMax *object);
void nmdbus_device_wi_max_set_rssi (NMDBusDeviceWiMax *object, gint value);

gint nmdbus_device_wi_max_get_cinr (NMDBusDeviceWiMax *object);
void nmdbus_device_wi_max_set_cinr (NMDBusDeviceWiMax *object, gint value);

gint nmdbus_device_wi_max_get_tx_power (NMDBusDeviceWiMax *object);
void nmdbus_device_wi_max_set_tx_power (NMDBusDeviceWiMax *object, gint value);

const gchar *nmdbus_device_wi_max_get_bsid (NMDBusDeviceWiMax *object);
gchar *nmdbus_device_wi_max_dup_bsid (NMDBusDeviceWiMax *object);
void nmdbus_device_wi_max_set_bsid (NMDBusDeviceWiMax *object, const gchar *value);

const gchar *nmdbus_device_wi_max_get_active_nsp (NMDBusDeviceWiMax *object);
gchar *nmdbus_device_wi_max_dup_active_nsp (NMDBusDeviceWiMax *object);
void nmdbus_device_wi_max_set_active_nsp (NMDBusDeviceWiMax *object, const gchar *value);


/* ---- */

#define NMDBUS_TYPE_DEVICE_WI_MAX_PROXY (nmdbus_device_wi_max_proxy_get_type ())
#define NMDBUS_DEVICE_WI_MAX_PROXY(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NMDBUS_TYPE_DEVICE_WI_MAX_PROXY, NMDBusDeviceWiMaxProxy))
#define NMDBUS_DEVICE_WI_MAX_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), NMDBUS_TYPE_DEVICE_WI_MAX_PROXY, NMDBusDeviceWiMaxProxyClass))
#define NMDBUS_DEVICE_WI_MAX_PROXY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NMDBUS_TYPE_DEVICE_WI_MAX_PROXY, NMDBusDeviceWiMaxProxyClass))
#define NMDBUS_IS_DEVICE_WI_MAX_PROXY(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NMDBUS_TYPE_DEVICE_WI_MAX_PROXY))
#define NMDBUS_IS_DEVICE_WI_MAX_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), NMDBUS_TYPE_DEVICE_WI_MAX_PROXY))

typedef struct _NMDBusDeviceWiMaxProxy NMDBusDeviceWiMaxProxy;
typedef struct _NMDBusDeviceWiMaxProxyClass NMDBusDeviceWiMaxProxyClass;
typedef struct _NMDBusDeviceWiMaxProxyPrivate NMDBusDeviceWiMaxProxyPrivate;

struct _NMDBusDeviceWiMaxProxy
{
  /*< private >*/
  GDBusProxy parent_instance;
  NMDBusDeviceWiMaxProxyPrivate *priv;
};

struct _NMDBusDeviceWiMaxProxyClass
{
  GDBusProxyClass parent_class;
};

GType nmdbus_device_wi_max_proxy_get_type (void) G_GNUC_CONST;

void nmdbus_device_wi_max_proxy_new (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
NMDBusDeviceWiMax *nmdbus_device_wi_max_proxy_new_finish (
    GAsyncResult        *res,
    GError             **error);
NMDBusDeviceWiMax *nmdbus_device_wi_max_proxy_new_sync (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);

void nmdbus_device_wi_max_proxy_new_for_bus (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
NMDBusDeviceWiMax *nmdbus_device_wi_max_proxy_new_for_bus_finish (
    GAsyncResult        *res,
    GError             **error);
NMDBusDeviceWiMax *nmdbus_device_wi_max_proxy_new_for_bus_sync (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);


/* ---- */

#define NMDBUS_TYPE_DEVICE_WI_MAX_SKELETON (nmdbus_device_wi_max_skeleton_get_type ())
#define NMDBUS_DEVICE_WI_MAX_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NMDBUS_TYPE_DEVICE_WI_MAX_SKELETON, NMDBusDeviceWiMaxSkeleton))
#define NMDBUS_DEVICE_WI_MAX_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), NMDBUS_TYPE_DEVICE_WI_MAX_SKELETON, NMDBusDeviceWiMaxSkeletonClass))
#define NMDBUS_DEVICE_WI_MAX_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NMDBUS_TYPE_DEVICE_WI_MAX_SKELETON, NMDBusDeviceWiMaxSkeletonClass))
#define NMDBUS_IS_DEVICE_WI_MAX_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NMDBUS_TYPE_DEVICE_WI_MAX_SKELETON))
#define NMDBUS_IS_DEVICE_WI_MAX_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), NMDBUS_TYPE_DEVICE_WI_MAX_SKELETON))

typedef struct _NMDBusDeviceWiMaxSkeleton NMDBusDeviceWiMaxSkeleton;
typedef struct _NMDBusDeviceWiMaxSkeletonClass NMDBusDeviceWiMaxSkeletonClass;
typedef struct _NMDBusDeviceWiMaxSkeletonPrivate NMDBusDeviceWiMaxSkeletonPrivate;

struct _NMDBusDeviceWiMaxSkeleton
{
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  NMDBusDeviceWiMaxSkeletonPrivate *priv;
};

struct _NMDBusDeviceWiMaxSkeletonClass
{
  GDBusInterfaceSkeletonClass parent_class;
};

GType nmdbus_device_wi_max_skeleton_get_type (void) G_GNUC_CONST;

NMDBusDeviceWiMax *nmdbus_device_wi_max_skeleton_new (void);


G_END_DECLS

#endif /* __NMDBUS_DEVICE_WIMAX_H__ */
