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

#include <sys/types.h>
#include <linux/quota.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>
#include <libuser/quota.h>
#include "Python.h"

#define FIXME	fprintf(stderr, "Function %s not implemented.\n", \
			__FUNCTION__); \
		DEBUG_EXIT; \
		return NULL;

#undef  DEBUG_BINDING
#ifdef  DEBUG
#define DEBUG_BINDING
#endif

#ifdef DEBUG_BINDING
#include <glib.h>
static int indent = 0;
static char *getindent()
{
	static char buf[LINE_MAX];
	g_return_val_if_fail(indent < sizeof(buf), "");
	memset(buf, 0, sizeof(buf));
	memset(buf, ' ', indent);
	return buf;
}
#define DEBUG_ENTRY {\
	fprintf(stderr, "%sEntering `%s' at line %d.\n", \
		getindent(), __FUNCTION__, __LINE__); \
	indent++; \
	}
#define DEBUG_CALL {\
      	fprintf(stderr, "%sIn `%s' at line %d.\n", \
		getindent(), __FUNCTION__, __LINE__); \
	}
#define DEBUG_EXIT {\
	indent--; \
	fprintf(stderr, "%sLeaving `%s' at line %d.\n", \
		getindent(), __FUNCTION__, __LINE__); \
	}
#else
#define DEBUG_ENTRY
#define DEBUG_CALL
#define DEBUG_EXIT
#endif

void initquota(void);

static PyTypeObject quota_object_type;
struct quota_struct {
	PyObject_HEAD
	char *user;
	char *group;
	char *special;
	int32_t inode_usage, inode_soft, inode_hard, inode_grace;
	int32_t block_usage, block_soft, block_hard, block_grace;
};

static void
quota_struct_dealloc(struct quota_struct *q)
{
	DEBUG_ENTRY;
	if(q->user)
		free(q->user);
	if(q->group)
		free(q->group);
	if(q->special)
		free(q->special);
	memset(q, 0, sizeof(struct quota_struct));
	free(q);
	DEBUG_EXIT;
}

static struct quota_struct *
quota_struct_new(const char *user, const char *group, const char *special,
		 int32_t inode_usage, int32_t inode_soft,
		 int32_t inode_hard, int32_t inode_grace,
		 int32_t block_usage, int32_t block_soft,
		 int32_t block_hard, int32_t block_grace)
{
	struct quota_struct *ret = NULL;

	DEBUG_ENTRY;
	ret = PyObject_NEW(struct quota_struct, &quota_object_type);
	if(ret == NULL) {
		DEBUG_EXIT;
		return NULL;
	}
	ret->user = user ? strdup(user) : NULL;
	ret->group = group ? strdup(group) : NULL;
	ret->special = special ? strdup(special) : NULL;
	ret->inode_usage = inode_usage;
	ret->inode_soft = inode_soft;
	ret->inode_hard = inode_hard;
	ret->inode_grace = inode_grace;
	ret->block_usage = block_usage;
	ret->block_soft = block_soft;
	ret->block_hard = block_hard;
	ret->block_grace = block_grace;
	DEBUG_EXIT;
	return ret;
}

static PyObject*
quota_struct_copy(struct quota_struct *self, PyObject *args)
{
	return (PyObject*)quota_struct_new(self->user, self->group,
					   self->special,
					   self->inode_usage, self->inode_soft,
					   self->inode_hard, self->inode_grace,
					   self->block_usage, self->block_soft,
					   self->block_hard, self->block_grace);
}

PyMethodDef quota_struct_methods[] = {
	{"copy", quota_struct_copy, 0, NULL},
	{NULL, NULL, 0, NULL},
};

static PyObject*
quota_struct_getattr(struct quota_struct *self, char *attr)
{
	DEBUG_ENTRY;
	if((self->user == NULL) && (self->group == NULL)) {
		PyErr_SetString(PyExc_RuntimeError, "invalid quota object");
		DEBUG_EXIT;
		return NULL;
	} else
	if(strcmp(attr, "user") == 0) {
		if(self->user == NULL) {
			PyErr_SetString(PyExc_RuntimeError, "not a user quota");
			DEBUG_EXIT;
			return NULL;
		} else {
			DEBUG_EXIT;
			return PyString_FromString(self->user);
		}
	} else
	if(strcmp(attr, "group") == 0) {
		if(self->group == NULL) {
			PyErr_SetString(PyExc_RuntimeError, "not a group quota");
			DEBUG_EXIT;
			return NULL;
		} else {
			DEBUG_EXIT;
			return PyString_FromString(self->group);
		}
	} else
	if(strcmp(attr, "special") == 0) {
		if(self->special == NULL) {
			PyErr_SetString(PyExc_RuntimeError, "no special device");
			DEBUG_EXIT;
			return NULL;
		} else {
			DEBUG_EXIT;
			return PyString_FromString(self->special);
		}
	} else
	if(strcmp(attr, "inode_usage") == 0) {
		DEBUG_EXIT;
		return PyInt_FromLong(self->inode_usage);
	}
	else
	if(strcmp(attr, "inode_soft") == 0) {
		DEBUG_EXIT;
		return PyInt_FromLong(self->inode_soft);
	}
	else
	if(strcmp(attr, "inode_hard") == 0) {
		DEBUG_EXIT;
		return PyInt_FromLong(self->inode_hard);
	}
	else
	if(strcmp(attr, "inode_grace") == 0) {
		DEBUG_EXIT;
		return PyInt_FromLong(self->inode_grace);
	}
	else
	if(strcmp(attr, "block_usage") == 0) {
		DEBUG_EXIT;
		return PyInt_FromLong(self->block_usage);
	}
	else
	if(strcmp(attr, "block_soft") == 0) {
		DEBUG_EXIT;
		return PyInt_FromLong(self->block_soft);
	}
	else
	if(strcmp(attr, "block_hard") == 0) {
		DEBUG_EXIT;
		return PyInt_FromLong(self->block_hard);
	}
	else
	if(strcmp(attr, "block_grace") == 0) {
		DEBUG_EXIT;
		return PyInt_FromLong(self->block_grace);
	} else {
		return Py_FindMethod(quota_struct_methods,
				     (PyObject*)self, attr);
	}
	DEBUG_EXIT;
	return Py_BuildValue("");
}

static int
quota_struct_setattr(struct quota_struct *self, char *attr, PyObject *args)
{
	DEBUG_ENTRY;
	if((self->user == NULL) && (self->group == NULL)) {
		PyErr_SetString(PyExc_RuntimeError, "invalid quota object");
		DEBUG_EXIT;
		return -1;
	}
	if(strcmp(attr, "user") == 0) {
		if(self->user == NULL) {
			PyErr_SetString(PyExc_RuntimeError, "not a user quota");
			DEBUG_EXIT;
			return -1;
		}
	}
	if(strcmp(attr, "group") == 0) {
		if(self->group == NULL) {
			PyErr_SetString(PyExc_RuntimeError, "not a group quota");
			DEBUG_EXIT;
			return -1;
		}
	}

	if(strcmp(attr, "user") == 0) {
		if(!PyString_Check(args)) {
			PyErr_SetString(PyExc_RuntimeError,
					"user must be a string");
			DEBUG_EXIT;
			return -1;
		}
		free(self->user);
		self->group = NULL;
		self->user = strdup(PyString_AsString(args));
	} else
	if(strcmp(attr, "group") == 0) {
		if(!PyString_Check(args)) {
			PyErr_SetString(PyExc_RuntimeError,
					"group must be a string");
			DEBUG_EXIT;
			return -1;
		}
		self->user = NULL;
		free(self->group);
		self->group = strdup(PyString_AsString(args));
	} else
	if(strcmp(attr, "special") == 0) {
		if(!PyString_Check(args)) {
			PyErr_SetString(PyExc_RuntimeError,
					"special must be a string");
			DEBUG_EXIT;
			return -1;
		}
		free(self->special);
		self->special = strdup(PyString_AsString(args));
	} else
	if(strcmp(attr, "inode_soft") == 0) {
		if(!PyInt_Check(args)) {
			PyErr_SetString(PyExc_RuntimeError,
					"inode_soft must be a number");
			DEBUG_EXIT;
			return -1;
		}
		self->inode_soft = PyInt_AsLong(args);
	} else
	if(strcmp(attr, "inode_hard") == 0) {
		if(!PyInt_Check(args)) {
			PyErr_SetString(PyExc_RuntimeError,
					"inode_hard must be a number");
			DEBUG_EXIT;
			return -1;
		}
		self->inode_hard = PyInt_AsLong(args);
	} else
	if(strcmp(attr, "inode_grace") == 0) {
		if(!PyInt_Check(args)) {
			PyErr_SetString(PyExc_RuntimeError,
					"inode_grace must be a number");
			DEBUG_EXIT;
			return -1;
		}
		self->inode_grace = PyInt_AsLong(args);
	} else
	if(strcmp(attr, "block_soft") == 0) {
		if(!PyInt_Check(args)) {
			PyErr_SetString(PyExc_RuntimeError,
					"block_soft must be a number");
			DEBUG_EXIT;
			return -1;
		}
		self->block_soft = PyInt_AsLong(args);
	} else
	if(strcmp(attr, "block_hard") == 0) {
		if(!PyInt_Check(args)) {
			PyErr_SetString(PyExc_RuntimeError,
					"block_hard must be a number");
			DEBUG_EXIT;
			return -1;
		}
		self->block_hard = PyInt_AsLong(args);
	} else
	if(strcmp(attr, "block_grace") == 0) {
		if(!PyInt_Check(args)) {
			PyErr_SetString(PyExc_RuntimeError,
					"block_grace must be a number");
			DEBUG_EXIT;
			return -1;
		}
		self->block_grace = PyInt_AsLong(args);
	} else {
		PyErr_SetString(PyExc_RuntimeError, "invalid attribute");
		DEBUG_EXIT;
		return -1;
	}
	DEBUG_EXIT;
	return 0;
}

static int
quota_struct_print(struct quota_struct *self, FILE *output, int flag)
{
	DEBUG_ENTRY;
	fprintf(output, "(user = '%s', group = '%s', special = '%s', "
		"inode_usage = %d, inode_soft = %d, inode_hard = %d, "
		"inode_grace = %d, block_usage = %d, block_soft = %d, "
		"block_hard = %d, block_grace = %d)",
		self->user ?: "(null)",
		self->group ?: "(null)",
		self->special ?: "(null)",
		self->inode_usage, self->inode_soft,
		self->inode_hard, self->inode_grace,
		self->block_usage, self->block_soft,
		self->block_hard, self->block_grace);
	DEBUG_EXIT;
	return 0;
}

static PyTypeObject quota_object_type = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,
	"quota_struct",
	sizeof(struct quota_struct),
	0,

	(destructor) quota_struct_dealloc,
	(printfunc) quota_struct_print,
	(getattrfunc) quota_struct_getattr,
	(setattrfunc) quota_struct_setattr,
	(cmpfunc) NULL,
	(reprfunc) NULL,

        (PyNumberMethods*) NULL,
        (PySequenceMethods*) NULL,
        (PyMappingMethods*) NULL,
        (hashfunc) NULL,
        (ternaryfunc) NULL,
        (reprfunc) NULL,
};

static PyObject*
quotamodule_get(PyObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *dict = NULL;
	int type = USRQUOTA, i;
	char *name = NULL, *special = NULL;
	char **specials = NULL;
	char *kwlist[] = {"type", "name", "special", NULL};
	int32_t inode_usage, inode_soft, inode_hard, inode_grace;
	int32_t block_usage, block_soft, block_hard, block_grace;
	long id;

	DEBUG_ENTRY;
	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "is|s", kwlist,
				        &type, &name, &special)) {
		if(!PyErr_Occurred())
			PyErr_SetString(PyExc_RuntimeError, "expected int, "
					"string, optional string");
		DEBUG_EXIT;
		return NULL;
	}
	if((type != USRQUOTA) && (type != GRPQUOTA)) {
		PyErr_SetString(PyExc_RuntimeError,
				"invalid type, expected USER or GROUP");
		DEBUG_EXIT;
		return NULL;
	}

	if(type == USRQUOTA) {
		struct passwd pwd, *res;
		char buf[LINE_MAX];
		if(getpwnam_r(name, &pwd, buf, sizeof(buf), &res) != 0) {
			PyErr_SetString(PyExc_RuntimeError,
					"invalid user name");
			DEBUG_EXIT;
			return NULL;
		}
		id = pwd.pw_uid;
	} else {
		struct group grp, *res;
		char buf[LINE_MAX];
		if(getgrnam_r(name, &grp, buf, sizeof(buf), &res) != 0) {
			PyErr_SetString(PyExc_RuntimeError,
					"invalid group name");
			DEBUG_EXIT;
			return NULL;
		}
		id = grp.gr_gid;
	}

	dict = PyDict_New();
	if(special == NULL) {
		specials = (type == USRQUOTA) ?
			quota_get_specials_user() :
			quota_get_specials_group();
		for(i = 0; (specials != NULL) && (specials[i] != NULL); i++) {
			if((type == USRQUOTA ?
			    quota_get_user(id, specials[i],
				           &inode_usage, &inode_soft,
					   &inode_hard, &inode_grace,
				           &block_usage, &block_soft,
					   &block_hard, &block_grace) :
			    quota_get_group(id, specials[i],
				            &inode_usage, &inode_soft,
					    &inode_hard, &inode_grace,
				            &block_usage, &block_soft,
					    &block_hard, &block_grace)) != 0) {
				PyErr_SetString(PyExc_RuntimeError,
						"error querying quota");
				DEBUG_EXIT;
				return NULL;
			}
			PyDict_SetItemString(dict, specials[i],
			      (type == USRQUOTA ?
			       quota_struct_new(name, NULL, specials[i],
						inode_usage, inode_soft,
						inode_hard, inode_grace,
						block_usage, block_soft,
						block_hard, block_grace) :
			       quota_struct_new(NULL, name, specials[i],
						inode_usage, inode_soft,
						inode_hard, inode_grace,
						block_usage, block_soft,
						block_hard, block_grace)));
		}
		quota_free_specials(specials);
	} else {
		PyDict_SetItemString(dict, special,
		      (type == USRQUOTA ?
		       quota_struct_new(name, NULL, special,
					inode_usage, inode_soft,
					inode_hard, inode_grace,
					block_usage, block_soft,
					block_hard, block_grace) :
		       quota_struct_new(NULL, name, special,
					inode_usage, inode_soft,
					inode_hard, inode_grace,
					block_usage, block_soft,
					block_hard, block_grace)));
	}

	DEBUG_EXIT;
	return dict;
}

static PyObject*
quotamodule_set(PyObject *self, PyObject *args)
{
	struct quota_struct *obj;
	DEBUG_ENTRY;

	if(PyList_Check(args)) {
		int i;
		for(i = 0; i < PyList_Size(args); i++) {
			if(quotamodule_set(self, PyList_GetItem(args, i)) == NULL){
				DEBUG_EXIT;
				return NULL;
			}
		}
		DEBUG_EXIT;
		return Py_BuildValue("");
	}

	if(!PyArg_ParseTuple(args, "O!", &quota_object_type, &obj)) {
		if(!PyErr_Occurred())
			PyErr_SetString(PyExc_RuntimeError,
					"expected quota_struct object");
		DEBUG_EXIT;
		return NULL;
	}
	if((obj->user == NULL) && (obj->group == NULL)) {
		PyErr_SetString(PyExc_RuntimeError, "invalid quota object");
		DEBUG_EXIT;
		return NULL;
	}
	if(obj->user) {
		struct passwd pwd, *res;
		char buf[LINE_MAX];
		if(getpwnam_r(obj->user, &pwd, buf, sizeof(buf), &res) != 0) {
			PyErr_SetString(PyExc_RuntimeError, "invalid user");
			DEBUG_EXIT;
			return NULL;
		}
		if(quota_set_user(pwd.pw_uid, obj->special,
				  obj->inode_soft, obj->inode_hard,
				  obj->inode_grace,
				  obj->block_soft, obj->block_hard,
				  obj->block_grace) != 0) {
			PyErr_SetString(PyExc_RuntimeError,
					"error setting quota limits");
			DEBUG_EXIT;
			return NULL;
		}
	} else {
		struct group grp, *res;
		char buf[LINE_MAX];
		if(getgrnam_r(obj->user, &grp, buf, sizeof(buf), &res) != 0) {
			PyErr_SetString(PyExc_RuntimeError, "invalid group");
			DEBUG_EXIT;
			return NULL;
		}
		if(quota_set_group(grp.gr_gid, obj->special,
				   obj->inode_soft, obj->inode_hard,
				   obj->inode_grace,
				   obj->block_soft, obj->block_hard,
				   obj->block_grace) != 0) {
			PyErr_SetString(PyExc_RuntimeError,
					"error setting quota limits");
			DEBUG_EXIT;
			return NULL;
		}
	}
	DEBUG_EXIT;
	return Py_BuildValue("");
}

static PyObject*
quotamodule_on(PyObject *self, PyObject *args, PyObject *kwargs)
{
	DEBUG_ENTRY;
	if(quota_on() != 0) {
		PyErr_SetString(PyExc_RuntimeError, "error enabling quotas");
		DEBUG_EXIT;
		return NULL;
	}
	DEBUG_EXIT;
	return Py_BuildValue("");
}

static PyObject*
quotamodule_off(PyObject *self, PyObject *args, PyObject *kwargs)
{
	DEBUG_ENTRY;
	if(quota_off() != 0) {
		PyErr_SetString(PyExc_RuntimeError,
				"error disabling quotas");
		DEBUG_EXIT;
		return NULL;
	}
	DEBUG_EXIT;
	return Py_BuildValue("");
}

static PyMethodDef
quota_methods[] = {
	{"get", (PyCFunction)quotamodule_get, METH_VARARGS | METH_KEYWORDS},
	{"set", (PyCFunction)quotamodule_set, METH_VARARGS | METH_KEYWORDS},
	{"on", (PyCFunction)quotamodule_on, METH_VARARGS | METH_KEYWORDS},
	{"off", (PyCFunction)quotamodule_off, METH_VARARGS | METH_KEYWORDS},
	{NULL, NULL, 0},
};

void
initquota(void)
{
	PyObject *module, *dict;
	DEBUG_ENTRY;
	module = Py_InitModule("quota", quota_methods);
	dict = PyModule_GetDict(module);
        PyDict_SetItemString(dict, "USER", PyInt_FromLong(USRQUOTA));
        PyDict_SetItemString(dict, "GROUP", PyInt_FromLong(GRPQUOTA));
	DEBUG_EXIT;
	return;
}
