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
 * Copyright (C) 2013 - Canonical Ltd.
 */

#ifndef NM_MODEM_OFONO_H
#define NM_MODEM_OFONO_H

#include <nm-modem-generic.h>

G_BEGIN_DECLS

#define NM_TYPE_MODEM_OFONO            (nm_modem_ofono_get_type ())
#define NM_MODEM_OFONO(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MODEM_OFONO, NMModemOfono))
#define NM_IS_MODEM_OFONO(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_MODEM_OFONO))
#define NM_MODEM_OFONO_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_MODEM_OFONO, NMModemOfonoClass))
#define NM_IS_MODEM_OFONO_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_MODEM_OFONO))
#define NM_MODEM_OFONO_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_MODEM_OFONO, NMModemOfonoClass))
#define NM_MODEM_OFONO_MODEM "modem"

typedef enum {
        NM_OFONO_ERROR_CONNECTION_NOT_OFONO = 0,  /*< nick=ConnectionNotOfono >*/
        NM_OFONO_ERROR_CONNECTION_INVALID,      /*< nick=ConnectionInvalid >*/
        NM_OFONO_ERROR_CONNECTION_INCOMPATIBLE, /*< nick=ConnectionIncompatible >*/
} NMOfonoError;

typedef struct {
	NMModem parent;
} NMModemOfono;

typedef struct {
	NMModemClass parent;
} NMModemOfonoClass;

GType nm_modem_ofono_get_type (void);

NMModem *nm_modem_ofono_new (const char *path);

G_END_DECLS

#endif /* NM_MODEM_OFONO_H */
