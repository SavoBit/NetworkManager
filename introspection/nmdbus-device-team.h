/*
 * Generated by gdbus-codegen 2.40.2. DO NOT EDIT.
 *
 * The license of this code is the same as for the source it was derived from.
 */

#ifndef __NMDBUS_DEVICE_TEAM_H__
#define __NMDBUS_DEVICE_TEAM_H__

#include <gio/gio.h>

G_BEGIN_DECLS


/* ------------------------------------------------------------------------ */
/* Declarations for org.freedesktop.NetworkManager.Device.Team */

#define NMDBUS_TYPE_DEVICE_TEAM (nmdbus_device_team_get_type ())
#define NMDBUS_DEVICE_TEAM(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NMDBUS_TYPE_DEVICE_TEAM, NMDBusDeviceTeam))
#define NMDBUS_IS_DEVICE_TEAM(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NMDBUS_TYPE_DEVICE_TEAM))
#define NMDBUS_DEVICE_TEAM_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE ((o), NMDBUS_TYPE_DEVICE_TEAM, NMDBusDeviceTeamIface))

struct _NMDBusDeviceTeam;
typedef struct _NMDBusDeviceTeam NMDBusDeviceTeam;
typedef struct _NMDBusDeviceTeamIface NMDBusDeviceTeamIface;

struct _NMDBusDeviceTeamIface
{
  GTypeInterface parent_iface;


  gboolean  (*get_carrier) (NMDBusDeviceTeam *object);

  const gchar * (*get_config) (NMDBusDeviceTeam *object);

  const gchar * (*get_hw_address) (NMDBusDeviceTeam *object);

  const gchar *const * (*get_slaves) (NMDBusDeviceTeam *object);

  void (*properties_changed) (
    NMDBusDeviceTeam *object,
    GVariant *arg_properties);

};

GType nmdbus_device_team_get_type (void) G_GNUC_CONST;

GDBusInterfaceInfo *nmdbus_device_team_interface_info (void);
guint nmdbus_device_team_override_properties (GObjectClass *klass, guint property_id_begin);


/* D-Bus signal emissions functions: */
void nmdbus_device_team_emit_properties_changed (
    NMDBusDeviceTeam *object,
    GVariant *arg_properties);



/* D-Bus property accessors: */
const gchar *nmdbus_device_team_get_hw_address (NMDBusDeviceTeam *object);
gchar *nmdbus_device_team_dup_hw_address (NMDBusDeviceTeam *object);
void nmdbus_device_team_set_hw_address (NMDBusDeviceTeam *object, const gchar *value);

gboolean nmdbus_device_team_get_carrier (NMDBusDeviceTeam *object);
void nmdbus_device_team_set_carrier (NMDBusDeviceTeam *object, gboolean value);

const gchar *const *nmdbus_device_team_get_slaves (NMDBusDeviceTeam *object);
gchar **nmdbus_device_team_dup_slaves (NMDBusDeviceTeam *object);
void nmdbus_device_team_set_slaves (NMDBusDeviceTeam *object, const gchar *const *value);

const gchar *nmdbus_device_team_get_config (NMDBusDeviceTeam *object);
gchar *nmdbus_device_team_dup_config (NMDBusDeviceTeam *object);
void nmdbus_device_team_set_config (NMDBusDeviceTeam *object, const gchar *value);


/* ---- */

#define NMDBUS_TYPE_DEVICE_TEAM_PROXY (nmdbus_device_team_proxy_get_type ())
#define NMDBUS_DEVICE_TEAM_PROXY(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NMDBUS_TYPE_DEVICE_TEAM_PROXY, NMDBusDeviceTeamProxy))
#define NMDBUS_DEVICE_TEAM_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), NMDBUS_TYPE_DEVICE_TEAM_PROXY, NMDBusDeviceTeamProxyClass))
#define NMDBUS_DEVICE_TEAM_PROXY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NMDBUS_TYPE_DEVICE_TEAM_PROXY, NMDBusDeviceTeamProxyClass))
#define NMDBUS_IS_DEVICE_TEAM_PROXY(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NMDBUS_TYPE_DEVICE_TEAM_PROXY))
#define NMDBUS_IS_DEVICE_TEAM_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), NMDBUS_TYPE_DEVICE_TEAM_PROXY))

typedef struct _NMDBusDeviceTeamProxy NMDBusDeviceTeamProxy;
typedef struct _NMDBusDeviceTeamProxyClass NMDBusDeviceTeamProxyClass;
typedef struct _NMDBusDeviceTeamProxyPrivate NMDBusDeviceTeamProxyPrivate;

struct _NMDBusDeviceTeamProxy
{
  /*< private >*/
  GDBusProxy parent_instance;
  NMDBusDeviceTeamProxyPrivate *priv;
};

struct _NMDBusDeviceTeamProxyClass
{
  GDBusProxyClass parent_class;
};

GType nmdbus_device_team_proxy_get_type (void) G_GNUC_CONST;

void nmdbus_device_team_proxy_new (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
NMDBusDeviceTeam *nmdbus_device_team_proxy_new_finish (
    GAsyncResult        *res,
    GError             **error);
NMDBusDeviceTeam *nmdbus_device_team_proxy_new_sync (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);

void nmdbus_device_team_proxy_new_for_bus (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
NMDBusDeviceTeam *nmdbus_device_team_proxy_new_for_bus_finish (
    GAsyncResult        *res,
    GError             **error);
NMDBusDeviceTeam *nmdbus_device_team_proxy_new_for_bus_sync (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);


/* ---- */

#define NMDBUS_TYPE_DEVICE_TEAM_SKELETON (nmdbus_device_team_skeleton_get_type ())
#define NMDBUS_DEVICE_TEAM_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NMDBUS_TYPE_DEVICE_TEAM_SKELETON, NMDBusDeviceTeamSkeleton))
#define NMDBUS_DEVICE_TEAM_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), NMDBUS_TYPE_DEVICE_TEAM_SKELETON, NMDBusDeviceTeamSkeletonClass))
#define NMDBUS_DEVICE_TEAM_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NMDBUS_TYPE_DEVICE_TEAM_SKELETON, NMDBusDeviceTeamSkeletonClass))
#define NMDBUS_IS_DEVICE_TEAM_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NMDBUS_TYPE_DEVICE_TEAM_SKELETON))
#define NMDBUS_IS_DEVICE_TEAM_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), NMDBUS_TYPE_DEVICE_TEAM_SKELETON))

typedef struct _NMDBusDeviceTeamSkeleton NMDBusDeviceTeamSkeleton;
typedef struct _NMDBusDeviceTeamSkeletonClass NMDBusDeviceTeamSkeletonClass;
typedef struct _NMDBusDeviceTeamSkeletonPrivate NMDBusDeviceTeamSkeletonPrivate;

struct _NMDBusDeviceTeamSkeleton
{
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  NMDBusDeviceTeamSkeletonPrivate *priv;
};

struct _NMDBusDeviceTeamSkeletonClass
{
  GDBusInterfaceSkeletonClass parent_class;
};

GType nmdbus_device_team_skeleton_get_type (void) G_GNUC_CONST;

NMDBusDeviceTeam *nmdbus_device_team_skeleton_new (void);


G_END_DECLS

#endif /* __NMDBUS_DEVICE_TEAM_H__ */