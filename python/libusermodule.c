/* Copyright (C) 2000,2001 Red Hat, Inc.
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ident "$Id$"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>
#include <libuser/user.h>
#include <libuser/user_private.h>
#include <Python.h>
#include "common.h"

#include "admin.c"
#include "ent.c"
#include "misc.c"

static PyObject*
libuser_get_user_shells(PyObject *ignored)
{
	GList *results = NULL;
	PyObject *ret = NULL;
	const char *shell;

	DEBUG_ENTRY;

	setusershell();
	while((shell = getusershell()) != NULL) {
		results = g_list_append(results, g_strdup(shell));
	}
	endusershell();

	ret = convert_glist_pystringlist(results);
	g_list_foreach(results, (GFunc)g_free, NULL);
	g_list_free(results);

	DEBUG_EXIT;
	return ret;
}

static PyMethodDef
libuser_methods[] = {
	{"admin", (PyCFunction)libuser_admin_new, METH_VARARGS | METH_KEYWORDS, "create a new administration context"},
	{"prompt", (PyCFunction)libuser_prompt_new, 0, "create and return a new prompt record"},
	{"get_user_shells", (PyCFunction)libuser_get_user_shells, 0, "return a list of valid shells"},
	{"ADMIN", (PyCFunction)libuser_admin_new, METH_VARARGS | METH_KEYWORDS, "create a new administration context"},
	{"PROMPT", (PyCFunction)libuser_prompt_new, 0, "create and return a new prompt record"},
	{"getUserShells", (PyCFunction)libuser_get_user_shells, 0, "return a list of valid shells"},
	{NULL, NULL, 0},
};

void
initlibuser(void)
{
	PyObject *module, *dict;
	DEBUG_ENTRY;
	module = Py_InitModule("libuser", libuser_methods);
	dict = PyModule_GetDict(module);
	PyDict_SetItemString(dict, "USER", PyInt_FromLong(lu_user));
	PyDict_SetItemString(dict, "GROUP", PyInt_FromLong(lu_group));
	PyDict_SetItemString(dict, "ADMINISTRATORUID", PyString_FromString(LU_ADMINISTRATORUID));
	PyDict_SetItemString(dict, "COMMONNAME", PyString_FromString(LU_COMMONNAME));
	PyDict_SetItemString(dict, "GECOS", PyString_FromString(LU_GECOS));
	PyDict_SetItemString(dict, "GID", PyString_FromString(LU_GID));
	PyDict_SetItemString(dict, "GIDNUMBER", PyString_FromString(LU_GIDNUMBER));
	PyDict_SetItemString(dict, "GROUPNAME", PyString_FromString(LU_GROUPNAME));
	PyDict_SetItemString(dict, "HOMEDIRECTORY", PyString_FromString(LU_HOMEDIRECTORY));
	PyDict_SetItemString(dict, "LOGINSHELL", PyString_FromString(LU_LOGINSHELL));
	PyDict_SetItemString(dict, "MEMBERUID", PyString_FromString(LU_MEMBERUID));
	PyDict_SetItemString(dict, "OBJECTCLASS", PyString_FromString(LU_OBJECTCLASS));
	PyDict_SetItemString(dict, "SHADOWEXPIRE", PyString_FromString(LU_SHADOWEXPIRE));
	PyDict_SetItemString(dict, "SHADOWFLAG", PyString_FromString(LU_SHADOWFLAG));
	PyDict_SetItemString(dict, "SHADOWINACTIVE", PyString_FromString(LU_SHADOWINACTIVE));
	PyDict_SetItemString(dict, "SHADOWLASTCHANGE", PyString_FromString(LU_SHADOWLASTCHANGE));
	PyDict_SetItemString(dict, "SHADOWMAX", PyString_FromString(LU_SHADOWMAX));
	PyDict_SetItemString(dict, "SHADOWMIN", PyString_FromString(LU_SHADOWMIN));
	PyDict_SetItemString(dict, "SHADOWWARNING", PyString_FromString(LU_SHADOWWARNING));
	PyDict_SetItemString(dict, "UID", PyString_FromString(LU_UID));
	PyDict_SetItemString(dict, "UIDNUMBER", PyString_FromString(LU_UIDNUMBER));
	PyDict_SetItemString(dict, "USERNAME", PyString_FromString(LU_USERNAME));
	PyDict_SetItemString(dict, "USERPASSWORD", PyString_FromString(LU_USERPASSWORD));
	DEBUG_EXIT;
}
