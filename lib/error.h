/*
 * Copyright (C) 2000-2002 Red Hat, Inc.
 *
 * This is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef libuser_error_h
#define libuser_error_h

#include <sys/types.h>
#include <errno.h>
#include <glib.h>

G_BEGIN_DECLS

enum lu_status {
	/* Non-fatal. */
	lu_success = 0,
	lu_warning_config_disabled,

	/* Fatal. */
	lu_error_generic,
	lu_error_privilege,
	lu_error_access_denied,

	/* Data validation errors. */
	lu_error_name_bad,
	lu_error_id_bad,
	lu_error_name_used,
	lu_error_id_used,

	/* Terminal manipulation errors. */
	lu_error_terminal,

	/* File I/O errors. */
	lu_error_open,
	lu_error_lock,
	lu_error_stat,
	lu_error_read,
	lu_error_write,
	lu_error_search,

	/* Initialization or module-loading errors. */
	lu_error_init,
	lu_error_module_load,
	lu_error_module_sym,
	lu_error_module_version,

	/* Since 0.53 */
	lu_error_unlock_empty,

	/* Since 0.56 */
	lu_error_invalid_attribute_value,

	/* Since 0.57 */
	lu_error_invalid_module_combination,
};
#ifndef __GTK_DOC_IGNORE__
#ifndef LU_DISABLE_DEPRECATED
typedef enum lu_status lu_status_t;
#endif
#endif

/**
 * lu_error:
 *
 * Error and status information.
 */
/* gtk-doc is dumb. */
struct lu_error;
struct lu_error {
	enum lu_status code;
	char *string;
};
#ifndef LU_DISABLE_DEPRECATED
/**
 * lu_error_t:
 *
 * An alias for struct #lu_error.
 * Deprecated: 0.57.3: Use struct #lu_error directly.
 */
typedef struct lu_error lu_error_t;
#endif

/**
 * LU_ERROR_CHECK:
 * @err_p_p: A pointer to a struct #lu_error * which will be checked.
 *
 * Checks that the given pointer to a pointer to a struct does not already
 * point to a valid #lu_error structure, and calls abort() on failure.  This
 * macro is used by many internal functions to check that an error has not
 * already occurred when they are invoked.
 */
#define LU_ERROR_CHECK(err_p_p) \
do { \
	struct lu_error **__err = (err_p_p); \
	if ((__err == NULL) || (*__err != NULL)) { \
		if(__err == NULL) { \
			fprintf(stderr, "libuser fatal error: %s() called with NULL " #err_p_p "\n", __FUNCTION__); \
		} else \
		if(*__err != NULL) { \
			fprintf(stderr, "libuser fatal error: %s() called with non-NULL *" #err_p_p "\n", __FUNCTION__); \
		} \
		abort(); \
	} \
} while(0)

void lu_error_new(struct lu_error **error, enum lu_status code,
		  const char *fmt, ...) G_GNUC_PRINTF(3, 4);
const char *lu_strerror(struct lu_error *error);
gboolean lu_error_is_success(enum lu_status status);
gboolean lu_error_is_warning(enum lu_status status);
gboolean lu_error_is_error(enum lu_status status);
void lu_error_free(struct lu_error **error);

G_END_DECLS

#endif
