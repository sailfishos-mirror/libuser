#include <libuser/user_private.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "util.h"

static gboolean
lu_files_create_backup(const char *filename)
{
	int ifd, ofd;
	char *backupname;
	struct stat ist, ost;
	gpointer lock;
	char buf[2048];
	size_t len;

	g_return_val_if_fail(filename != NULL, FALSE);
	g_return_val_if_fail(strlen(filename) > 0, FALSE);

	ifd = open(filename, O_RDONLY);
	if(ifd == -1) {
		g_warning(_("Couldn't open '%s'.\n"), filename);
		return FALSE;
	}
	if(fstat(ifd, &ist) == -1) {
		close(ifd);
		g_warning(_("Couldn't stat '%s'.\n"), filename);
		return FALSE;
	}

	backupname = g_strconcat(filename, "-", NULL);
	ofd = open(backupname, O_WRONLY | O_CREAT, ist.st_mode);
	if(ofd == -1) {
		g_warning(_("Couldn't create '%s'.\n"), backupname);
		g_free(backupname);
		close(ifd);
		return FALSE;
	}

	if((fstat(ofd, &ost) == -1) || !S_ISREG(ost.st_mode)) {
		g_warning(_("Couldn't stat '%s'.\n"), backupname);
		g_free(backupname);
		close(ofd);
		return FALSE;
	}

	lock = lock_obtain(ofd);
	if(lock == NULL) {
		g_warning(_("Couldn't lock '%s'.\n"), backupname);
		g_free(backupname);
		close(ofd);
		return FALSE;
	}

	do {
		len = read(ifd, buf, sizeof(buf));
		if(len >= 0) {
			write(ofd, buf, len);
		}
	} while(len == sizeof(buf));
	fsync(ofd);
	ftruncate(ofd, lseek(ofd, 0, SEEK_CUR));

	if(fstat(ofd, &ost) == -1) {
		g_warning(_("Couldn't stat '%s'.\n"), backupname);
		g_free(backupname);
		close(ofd);
		return FALSE;
	}
	close(ofd);

	if(ist.st_size != ost.st_size) {
		return FALSE;
	}

	g_free(backupname);

	return TRUE;
}

static gboolean
lu_files_parse_user_entry(const gchar *line, struct lu_ent *ent)
{
	gchar **v = NULL;
	gchar *crypted = NULL, *tmp = NULL;

	g_return_val_if_fail(line != NULL, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);

	v = g_strsplit(line, ":", 6);

	if(lu_strv_len(v) < 6) {
		g_warning("Passwd entry is incorrectly formatted.");
		return FALSE;
	}

	lu_ent_add_original(ent, LU_OBJECTCLASS, "posixAccount");
	lu_ent_set_original(ent, LU_USERNAME, v[0]);
	tmp = g_strconcat("{crypt}", v[1], NULL);
	crypted = ent->vcache->cache(ent->vcache, tmp);
	g_free(tmp);
	lu_ent_set_original(ent, LU_USERPASSWORD, crypted);
	lu_ent_set_original(ent, LU_UIDNUMBER, v[2]);
	lu_ent_set_original(ent, LU_GIDNUMBER, v[3]);
	lu_ent_set_original(ent, LU_GECOS, v[4]);
	lu_ent_set_original(ent, LU_HOMEDIRECTORY, v[5]);
	lu_ent_set_original(ent, LU_LOGINSHELL, v[6] ? v[6] : "");

	g_strfreev(v);

	return TRUE;
}

static gboolean
lu_files_parse_group_entry(const gchar *line, struct lu_ent *ent)
{
	gchar **v = NULL;
	gchar *p = NULL, *q = NULL;
	gchar *crypted, *tmp;

	g_return_val_if_fail(line != NULL, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);

	v = g_strsplit(line, ":", 3);

	if(lu_strv_len(v) < 3) {
		g_warning("Group entry is incorrectly formatted.");
		return FALSE;
	}

	lu_ent_add_original(ent, LU_OBJECTCLASS, "posixGroup");
	lu_ent_set_original(ent, LU_GROUPNAME, v[0]);
	tmp = g_strconcat("{crypt}", v[1], NULL);
	crypted = ent->vcache->cache(ent->vcache, tmp);
	g_free(tmp);
	lu_ent_set_original(ent, LU_USERPASSWORD, crypted);
	lu_ent_set_original(ent, LU_GIDNUMBER, v[2] ? v[2] : "");

	if(v[3] != NULL) {
		for(p = strtok_r(v[3], ",", &q);
		    p && *p;
		    p = strtok_r(NULL, ",", &q)) {
			lu_ent_add_original(ent, LU_MEMBERUID, p);
		}
	}

	g_strfreev(v);

	return TRUE;
}

static gboolean
lu_shadow_parse_user_entry(const gchar *line, struct lu_ent *ent)
{
	gchar **v = NULL;
	gchar *crypted, *tmp;

	g_return_val_if_fail(line != NULL, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);

	v = g_strsplit(line, ":", 8);

	if(lu_strv_len(v) < 8) {
		g_warning("User shadow entry is incorrectly formatted.");
		return FALSE;
	}

	lu_ent_add_original(ent, LU_OBJECTCLASS, "shadowAccount");
	lu_ent_set_original(ent, LU_USERNAME, v[0]);
	tmp = g_strconcat("{crypt}", v[1], NULL);
	crypted = ent->vcache->cache(ent->vcache, tmp);
	g_free(tmp);
	lu_ent_set_original(ent, LU_USERPASSWORD, crypted);
	lu_ent_set_original(ent, LU_SHADOWLASTCHANGE, v[2]);
	lu_ent_set_original(ent, LU_SHADOWMIN, v[3]);
	lu_ent_set_original(ent, LU_SHADOWMAX, v[4]);
	lu_ent_set_original(ent, LU_SHADOWWARNING, v[5]);
	lu_ent_set_original(ent, LU_SHADOWINACTIVE, v[6]);
	lu_ent_set_original(ent, LU_SHADOWEXPIRE, v[7]);
	lu_ent_set_original(ent, LU_SHADOWFLAG, v[8] ? v[8] : "");

	g_strfreev(v);

	return TRUE;
}

static gboolean
lu_shadow_parse_group_entry(const gchar *line, struct lu_ent *ent)
{
	gchar **v = NULL;
	gchar *p, *q;
	gchar *crypted, *tmp;

	g_return_val_if_fail(line != NULL, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);

	v = g_strsplit(line, ":", 3);

	if(lu_strv_len(v) < 3) {
		g_warning("Group shadow entry is incorrectly formatted.");
		return FALSE;
	}

	lu_ent_add_original(ent, LU_OBJECTCLASS, "shadowAccount");
	lu_ent_set_original(ent, LU_GROUPNAME, v[0]);
	tmp = g_strconcat("{crypt}", v[1], NULL);
	crypted = ent->vcache->cache(ent->vcache, tmp);
	g_free(tmp);
	lu_ent_set_original(ent, LU_USERPASSWORD, crypted);

	if(v[2]) {
		for(p = strtok_r(v[2], ",", &q);
		    p && *p;
		    p = strtok_r(NULL, ",", &q)) {
			lu_ent_add_original(ent, LU_ADMINISTRATORUID, p);
		}
	}

	if(v[3]) {
		for(p = strtok_r(v[3], ",", &q);
		    p && *p;
		    p = strtok_r(NULL, ",", &q)) {
			lu_ent_add_original(ent, LU_MEMBERUID, p);
		}
	}

	g_strfreev(v);

	return TRUE;
}

typedef gboolean (*parse_fn)(const gchar *line, struct lu_ent *ent);

static gboolean
generic_lookup(struct lu_module *module, const char *module_name,
	       const char *base_name, gconstpointer name,
	       parse_fn parser, int field, struct lu_ent *ent)
{
	gboolean ret = FALSE;
	gpointer lock;
	GList *dir;
	int fd = -1;
	char *line, *filename, *key;

	g_return_val_if_fail(module != NULL, FALSE);
	g_return_val_if_fail(module_name != NULL, FALSE);
	g_return_val_if_fail(strlen(module_name) > 0, FALSE);
	g_return_val_if_fail(base_name != NULL, FALSE);
	g_return_val_if_fail(strlen(base_name) > 0, FALSE);
	g_return_val_if_fail(name != NULL, FALSE);
	g_return_val_if_fail(parser != NULL, FALSE);
	g_return_val_if_fail(field > 0, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);

	key = g_strconcat(module_name, "/directory", NULL);
	dir = lu_cfg_read(module->lu_context, key, "/etc");
	filename = g_strconcat((char*)dir->data, "/", base_name, NULL);
	g_free(key);
	g_list_free(dir);

	fd = open(filename, O_RDONLY);
	if(fd != -1) {
		lock = lock_obtain(fd);
		line = get_matching_linex(fd, (char*) name, field);
		if(line != NULL) {
			ret = parser(line, ent);
			g_free(line);
		}
		lock_free(fd, lock);
		close(fd);
	}

	g_free(filename);

	return ret;
}

static gboolean
lu_files_user_lookup_name(struct lu_module *module,
		          gconstpointer name, struct lu_ent *ent)
{
	return generic_lookup(module, "files", "passwd", name,
			      lu_files_parse_user_entry, 1, ent);
}

static gboolean
lu_files_user_lookup_id(struct lu_module *module,
		        gconstpointer id, struct lu_ent *ent)
{
	char *key;
	gboolean ret = FALSE;
	key = g_strdup_printf("%d", GPOINTER_TO_INT(id));
	ret = generic_lookup(module, "files", "passwd", key,
			     lu_files_parse_user_entry, 3, ent);
	g_free(key);
	return ret;
}

static gboolean
lu_shadow_user_lookup_name(struct lu_module *module,
		           gconstpointer name, struct lu_ent *ent)
{
	return generic_lookup(module, "shadow", "shadow", name,
			      lu_shadow_parse_user_entry, 1, ent);
}

static gboolean
lu_shadow_user_lookup_id(struct lu_module *module,
		         gconstpointer id, struct lu_ent *ent)
{
	char *key;
	GList *values;
	gboolean ret = FALSE;
	key = g_strdup_printf("%d", GPOINTER_TO_INT(id));
	ret = lu_files_user_lookup_id(module, id, ent);
	if(ret) {
		values = lu_ent_get(ent, LU_USERNAME);
		if(values && values->data) {
			ret = generic_lookup(module, "shadow", "shadow",
					     values->data,
					     lu_shadow_parse_user_entry,
					     1, ent);
		}
	}
	g_free(key);
	return ret;
}

static gboolean
lu_files_group_lookup_name(struct lu_module *module,
			   gconstpointer name, struct lu_ent *ent)
{
	return generic_lookup(module, "files", "group", name,
			      lu_files_parse_group_entry, 1, ent);
}

static gboolean
lu_files_group_lookup_id(struct lu_module *module,
		         gconstpointer id, struct lu_ent *ent)
{
	char *key;
	gboolean ret = FALSE;
	key = g_strdup_printf("%d", GPOINTER_TO_INT(id));
	ret = generic_lookup(module, "files", "group", key,
			     lu_files_parse_group_entry, 3, ent);
	g_free(key);
	return ret;
}

static gboolean
lu_shadow_group_lookup_name(struct lu_module *module,
			    gconstpointer name, struct lu_ent *ent)
{
	return generic_lookup(module, "shadow", "gshadow", name,
			      lu_shadow_parse_group_entry, 1, ent);
}

static gboolean
lu_shadow_group_lookup_id(struct lu_module *module,
		          gconstpointer id, struct lu_ent *ent)
{
	char *key;
	GList *values;
	gboolean ret = FALSE;
	key = g_strdup_printf("%d", GPOINTER_TO_INT(id));
	ret = lu_files_group_lookup_id(module, id, ent);
	if(ret) {
		values = lu_ent_get(ent, LU_GROUPNAME);
		if(values && values->data) {
			ret = generic_lookup(module, "shadow", "gshadow",
					     values->data,
					     lu_shadow_parse_group_entry,
					     1, ent);
		}
	}
	g_free(key);
	return ret;
}

static char *
lu_files_format_user(struct lu_ent *ent)
{
	GList *uid = NULL, *userPassword = NULL, *uidNumber = NULL,
	      *gidNumber = NULL, *gecos = NULL, *loginShell = NULL,
	      *homeDirectory = NULL, *i = NULL;
	char *line = NULL, *userPasswordString = NULL, *tmp = NULL;

	g_return_val_if_fail(ent != NULL, NULL);

	uid = lu_ent_get(ent, LU_USERNAME);
	g_return_val_if_fail(uid != NULL, NULL);
	userPassword = lu_ent_get(ent, LU_USERPASSWORD);
	g_return_val_if_fail(userPassword != NULL, NULL);
	uidNumber = lu_ent_get(ent, LU_UIDNUMBER);
	g_return_val_if_fail(uidNumber != NULL, NULL);
	gidNumber = lu_ent_get(ent, LU_GIDNUMBER);
	g_return_val_if_fail(gidNumber != NULL, NULL);
	gecos = lu_ent_get(ent, LU_GECOS);
	g_return_val_if_fail(gecos != NULL, NULL);
	homeDirectory = lu_ent_get(ent, LU_HOMEDIRECTORY);
	g_return_val_if_fail(homeDirectory != NULL, NULL);
	loginShell = lu_ent_get(ent, LU_LOGINSHELL);
	g_return_val_if_fail(loginShell != NULL, NULL);

	userPasswordString = userPassword->data;
	for(i = userPassword; i; i = g_list_next(i)) {
		if(strncmp(i->data, "{crypt}", 7) == 0) {
			userPasswordString = ((char*)i->data) + 7;
		}
	}

	if((uid != NULL) && (uid->data != NULL) &&
	   (userPasswordString != NULL) &&
	   (uidNumber != NULL) && (uidNumber->data != NULL) &&
	   (gidNumber != NULL) && (gidNumber->data != NULL) &&
	   (gecos != NULL) && (gecos->data != NULL) &&
	   (homeDirectory != NULL) && (homeDirectory->data != NULL)) {
		tmp = g_strdup_printf("%s:%s:%s:%s:%s:%s:%s\n",
				      (char*) uid->data,
				      (char*) userPasswordString,
				      (char*) uidNumber->data,
				      (char*) gidNumber->data,
				      (char*) gecos->data,
				      (char*) homeDirectory->data,
				      (char*) loginShell->data);
		line = ent->vcache->cache(ent->vcache, tmp);
		g_free(tmp);
	}

	return line;
}

static char *
lu_files_format_group(struct lu_ent *ent)
{
	GList *gid = NULL, *userPassword = NULL,
	      *gidNumber = NULL, *memberUid = NULL, *l = NULL;
	char *line = NULL, *tmp = NULL, *userPasswordString = NULL;
	int i;

	g_return_val_if_fail(ent != NULL, NULL);

	gid = lu_ent_get(ent, LU_GROUPNAME);
	userPassword = lu_ent_get(ent, LU_USERPASSWORD);
	g_return_val_if_fail(userPassword != NULL, NULL);
	gidNumber = lu_ent_get(ent, LU_GIDNUMBER);
	g_return_val_if_fail(gidNumber != NULL, NULL);
	memberUid = lu_ent_get(ent, LU_MEMBERUID);

	userPasswordString = userPassword->data;
	for(l = userPassword; l; l = g_list_next(l)) {
		if(strncmp(l->data, "{crypt}", 7) == 0) {
			userPasswordString = ((char*)l->data) + 7;
		}
	}

	if((gid != NULL) && (gid->data != NULL) &&
	   (userPasswordString != NULL) &&
	   (gidNumber != NULL) && (gidNumber->data != NULL)) {
		tmp = g_strdup_printf("%s:%s:%s:",
				      (char*) gid->data,
				      (char*) userPasswordString,
				      (char*) gidNumber->data);
		line = ent->vcache->cache(ent->vcache, tmp);
		g_free(tmp);

		for(i = 0; memberUid && g_list_nth(memberUid, i); i++) {
			l = g_list_nth(memberUid, i);
			tmp = g_strconcat(line, i ? "," : "", l->data, NULL);
			line = ent->vcache->cache(ent->vcache, tmp);
			g_free(tmp);
		}

		tmp = g_strconcat(line, "\n", NULL);
		line = ent->vcache->cache(ent->vcache, tmp);
		g_free(tmp);
	}

	return line;
}

static char *
lu_shadow_format_user(struct lu_ent *ent)
{
	GList *uid = NULL, *userPassword = NULL, *shadowLastChange = NULL,
	      *shadowMin = NULL, *shadowMax = NULL, *shadowWarning = NULL,
	      *shadowInactive = NULL, *shadowExpire = NULL, *shadowFlag = NULL,
	      *i = NULL;
	char *userPasswordString = NULL, *line = NULL, *tmp = NULL;

	g_return_val_if_fail(ent != NULL, NULL);

	uid = lu_ent_get(ent, LU_USERNAME);
	g_return_val_if_fail(uid != NULL, NULL);
	userPassword = lu_ent_get(ent, LU_USERPASSWORD);
	g_return_val_if_fail(userPassword != NULL, NULL);
	shadowLastChange = lu_ent_get(ent, LU_SHADOWLASTCHANGE);
	g_return_val_if_fail(shadowLastChange != NULL, NULL);
	shadowMin = lu_ent_get(ent, LU_SHADOWMIN);
	g_return_val_if_fail(shadowMin != NULL, NULL);
	shadowMax = lu_ent_get(ent, LU_SHADOWMAX);
	g_return_val_if_fail(shadowMax != NULL, NULL);
	shadowWarning = lu_ent_get(ent, LU_SHADOWWARNING);
	g_return_val_if_fail(shadowWarning != NULL, NULL);
	shadowInactive = lu_ent_get(ent, LU_SHADOWINACTIVE);
	g_return_val_if_fail(shadowInactive != NULL, NULL);
	shadowExpire = lu_ent_get(ent, LU_SHADOWEXPIRE);
	g_return_val_if_fail(shadowExpire != NULL, NULL);
	shadowFlag = lu_ent_get(ent, LU_SHADOWFLAG);
	g_return_val_if_fail(shadowFlag != NULL, NULL);

	userPasswordString = userPassword->data;
	for(i = userPassword; i; i = g_list_next(i)) {
		if(strncmp(i->data, "{crypt}", 7) == 0) {
			userPasswordString = ((char*)i->data) + 7;
		}
	}

	if((uid != NULL) && (uid->data != NULL) &&
	   (userPasswordString != NULL) &&
	   (shadowLastChange != NULL) && (shadowLastChange->data != NULL) &&
	   (shadowMin != NULL) && (shadowMin->data != NULL) &&
	   (shadowMax != NULL) && (shadowMax->data != NULL) &&
	   (shadowWarning != NULL) && (shadowWarning->data != NULL) &&
	   (shadowInactive != NULL) && (shadowInactive->data != NULL) &&
	   (shadowExpire != NULL) && (shadowExpire->data != NULL)) {
		tmp = g_strdup_printf("%s:%s:%s:%s:%s:%s:%s:%s:%s\n",
				      (char*) uid->data,
				      (char*) userPasswordString,
				      (char*) shadowLastChange->data,
				      (char*) shadowMin->data,
				      (char*) shadowMax->data,
				      (char*) shadowWarning->data,
				      (char*) shadowInactive->data,
				      (char*) shadowExpire->data,
				      (char*) shadowFlag->data);
		line = ent->vcache->cache(ent->vcache, tmp);
		g_free(tmp);
	}

	return line;
}

static char *
lu_shadow_format_group(struct lu_ent *ent)
{
	GList *gid = NULL, *userPassword = NULL, *administratorUid = NULL,
	      *memberUid = NULL, *l = NULL;
	char *line = NULL, *userPasswordString = NULL, *tmp = NULL;
	int i;

	g_return_val_if_fail(ent != NULL, NULL);

	gid = lu_ent_get(ent, LU_GROUPNAME);
	g_return_val_if_fail(gid != NULL, NULL);
	userPassword = lu_ent_get(ent, LU_USERPASSWORD);
	g_return_val_if_fail(userPassword != NULL, NULL);
	administratorUid = lu_ent_get(ent, LU_ADMINISTRATORUID);
	memberUid = lu_ent_get(ent, LU_MEMBERUID);

	userPasswordString = userPassword->data;
	for(l = userPassword; l; l = g_list_next(l)) {
		if(strncmp(l->data, "{crypt}", 7) == 0) {
			userPasswordString = ((char*)l->data) + 7;
		}
	}

	if((gid != NULL) && (gid->data != NULL) &&
	   (userPasswordString != NULL)) {
		line = g_strdup_printf("%s:%s:",
				       (char*) gid->data,
				       (char*) userPasswordString);

		for(i = 0;
		    administratorUid && g_list_nth(administratorUid, i);
		    i++) {
			l = g_list_nth(administratorUid, i);
			tmp = g_strconcat(line, i ? "," : "", l->data, NULL);
			line = ent->vcache->cache(ent->vcache, tmp);
			g_free(tmp);
		}

		tmp = g_strconcat(line, ":", NULL);
		line = ent->vcache->cache(ent->vcache, tmp);
		g_free(tmp);

		for(i = 0;
		    memberUid && g_list_nth(memberUid, i);
		    i++) {
			l = g_list_nth(memberUid, i);
			tmp = g_strconcat(line, i ? "," : "", l->data, NULL);
			line = ent->vcache->cache(ent->vcache, tmp);
			g_free(tmp);
		}

		tmp = g_strconcat(line, "\n", NULL);
		line = ent->vcache->cache(ent->vcache, tmp);
		g_free(tmp);
	}
	return line;
}

typedef char * (*format_fn)(struct lu_ent *ent);

static gboolean
generic_add(struct lu_module *module, const char *module_name,
	    const char *base_name, format_fn formatter, struct lu_ent *ent)
{
	GList *dir;
	char *key, *line, *filename, *contents;
	int fd;
	struct stat st;
	off_t offset;
	gpointer lock;
	gboolean ret = FALSE;

	g_return_val_if_fail(module != NULL, FALSE);
	g_return_val_if_fail(module_name != NULL, FALSE);
	g_return_val_if_fail(strlen(module_name) > 0, FALSE);
	g_return_val_if_fail(base_name != NULL, FALSE);
	g_return_val_if_fail(strlen(base_name) > 0, FALSE);
	g_return_val_if_fail(formatter != NULL, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);

	key = g_strconcat(module_name, "/directory", NULL);
	dir = lu_cfg_read(module->lu_context, key, "/etc");
	filename = g_strconcat((char*)dir->data, "/", base_name, NULL);
	g_free(key);
	g_list_free(dir);

	g_return_val_if_fail(lu_files_create_backup(filename), FALSE);

	fd = open(filename, O_RDWR);
	if(fd != -1) {
		lock = lock_obtain(fd);
		if(fstat(fd, &st) != -1) {
			line = formatter(ent);
			contents = g_malloc0(st.st_size + 1 + strlen(line) + 1);
			if(line && strchr(line, ':')) {
				char *fragment1, *fragment2;
				fragment1 = g_strndup(line, strchr(line, ':') - line + 1);
				fragment2 = g_strconcat("\n", fragment1, NULL);
				if(read(fd, contents, st.st_size) == st.st_size) {
					if(strncmp(contents, fragment1, strlen(fragment1)) == 0) {
						ret = FALSE;
					} else
					if(strstr(contents, fragment2) != NULL) {
						ret = FALSE;
					} else
					if(((offset = lseek(fd, 0, SEEK_END)) != -1)) {
						if(write(fd, line, strlen(line)) == strlen(line)) {
							ret = TRUE;
						} else {
							ret = FALSE;
							ftruncate(fd, offset);
						}
					}
				}
				g_free(fragment1);
				g_free(fragment2);
			}
			g_free(contents);
		}
		lock_free(fd, lock);
		close(fd);
	}
	g_free(filename);

	return ret;
}

static gboolean
lu_files_user_add(struct lu_module *module, struct lu_ent *ent)
{
	return generic_add(module, "files", "passwd",
			   lu_files_format_user, ent);
}

static gboolean
lu_shadow_user_add(struct lu_module *module, struct lu_ent *ent)
{
	gboolean ret = generic_add(module, "shadow", "shadow",
				   lu_shadow_format_user, ent);
	if(ret) {
		lu_ent_set(ent, LU_USERPASSWORD, "x");
	}
	return ret;
}

static gboolean
lu_files_group_add(struct lu_module *module, struct lu_ent *ent)
{
	return generic_add(module, "files", "group",
			   lu_files_format_group, ent);
}

static gboolean
lu_shadow_group_add(struct lu_module *module, struct lu_ent *ent)
{
	gboolean ret = generic_add(module, "shadow", "gshadow",
				   lu_shadow_format_group, ent);
	if(ret) {
		lu_ent_set(ent, LU_USERPASSWORD, "x");
	}
	return ret;
}

static gboolean
generic_mod(struct lu_module *module, const char *module_name,
	    const char *base_name, format_fn formatter, struct lu_ent *ent)
{
	char *filename = NULL, *line = NULL, *contents = NULL, *key = NULL;
	struct stat st;
	int fd = -1;
	GList *dir = NULL, *name = NULL;
	gboolean ret = FALSE;
	gpointer lock = NULL;

	g_return_val_if_fail(module != NULL, FALSE);
	g_return_val_if_fail(module_name != NULL, FALSE);
	g_return_val_if_fail(strlen(module_name) > 0, FALSE);
	g_return_val_if_fail(base_name != NULL, FALSE);
	g_return_val_if_fail(strlen(base_name) > 0, FALSE);
	g_return_val_if_fail(formatter != NULL, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);

	if(ent->type == lu_user)
		name = lu_ent_get_original(ent, LU_USERNAME);
	if(ent->type == lu_group)
		name = lu_ent_get_original(ent, LU_GROUPNAME);
	g_return_val_if_fail(name != NULL, FALSE);
	g_return_val_if_fail(name->data != NULL, FALSE);

	key = g_strconcat(module_name, "/directory", NULL);
	dir = lu_cfg_read(module->lu_context, key, "/etc");
	filename = g_strconcat((char*)dir->data, "/", base_name, NULL);
	g_free(key);
	g_list_free(dir);

	g_return_val_if_fail(lu_files_create_backup(filename), FALSE);

	fd = open(filename, O_RDWR);
	if(fd != -1) {
		lock = lock_obtain(fd);
		if(fstat(fd, &st) != -1) {
			line = formatter(ent);
			contents = g_malloc0(st.st_size + 1 + strlen(line) + 1);
			if(line && strchr(line, ':')) {
				char *namestr, *fragment1, *fragment2;
				namestr = name->data;
				fragment1 = g_strconcat(namestr, ":", NULL);
				fragment2 = g_strconcat("\n", fragment1, NULL);
				if(read(fd, contents, st.st_size) == st.st_size) {
					lseek(fd, 0, SEEK_SET);
					if(strncmp(contents, fragment1, strlen(fragment1)) == 0) {
						/* At the very beginning. */
						if(strchr(contents, '\n')) {
							char *p = strchr(contents, '\n') + 1;
							/* Replace the first line. */
							memmove(contents + strlen(line), p, strlen(contents) + 1);
							memcpy(contents, line, strlen(line));
						} else {
							/* Replace the only line. */
							strcpy(contents, line);
						}
					} else
					if(strstr(contents, fragment2)) {
						/* On a subsequent line. */
						char *p = strstr(contents, fragment2) + 1;
						char *q = strchr(p, '\n');
						if(q) {
							/* Replace the nth line. */
							q++;
							memmove(p + strlen(line), q, strlen(contents) + 1 - (q - contents));
							memcpy(p, line, strlen(line));

						} else {
							/* Replace the last line. */
							strcpy(p, line);
						}
					}
					if(write(fd, contents, strlen(contents)) == strlen(contents)) {
						ftruncate(fd, strlen(contents));
						ret = TRUE;
					}
				}
				g_free(fragment1);
				g_free(fragment2);
			}
			g_free(contents);
		}
		lock_free(fd, lock);
		close(fd);
	}

	g_free(filename);

	return ret;
}

static gboolean
lu_files_user_mod(struct lu_module *module, struct lu_ent *ent)
{
	return generic_mod(module, "files", "passwd", lu_files_format_user, ent);
}

static gboolean
lu_files_group_mod(struct lu_module *module, struct lu_ent *ent)
{
	return generic_mod(module, "files", "group", lu_files_format_group, ent);
}

static gboolean
lu_shadow_user_mod(struct lu_module *module, struct lu_ent *ent)
{
	gboolean ret = generic_mod(module, "shadow", "shadow",
				   lu_shadow_format_user, ent);
	if(ret) {
		lu_ent_set(ent, LU_USERPASSWORD, "x");
	}
	return ret;
}

static gboolean
lu_shadow_group_mod(struct lu_module *module, struct lu_ent *ent)
{
	gboolean ret = generic_mod(module, "shadow", "gshadow",
				   lu_shadow_format_group, ent);
	if(ret) {
		lu_ent_set(ent, LU_USERPASSWORD, "x");
	}
	return ret;
}

static gboolean
generic_del(struct lu_module *module, const char *module_name,
	    const char *base_name, struct lu_ent *ent)
{
	GList *name = NULL, *dir = NULL;
	char *contents = NULL, *filename = NULL, *line, *key = NULL, *tmp;
	struct stat st;
	int fd = -1;
	gpointer lock = NULL;
	gboolean ret = FALSE;

	if(ent->type == lu_user)
		name = lu_ent_get_original(ent, LU_USERNAME);
	if(ent->type == lu_group)
		name = lu_ent_get_original(ent, LU_GROUPNAME);
	g_return_val_if_fail(name != NULL, FALSE);

	g_return_val_if_fail(module != NULL, FALSE);
	g_return_val_if_fail(module_name != NULL, FALSE);
	g_return_val_if_fail(strlen(module_name) > 0, FALSE);
	g_return_val_if_fail(base_name != NULL, FALSE);
	g_return_val_if_fail(strlen(base_name) > 0, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);

	key = g_strconcat(module_name, "/directory", NULL);
	dir = lu_cfg_read(module->lu_context, key, "/etc");
	filename = g_strconcat((char*)dir->data, "/", base_name, NULL);
	g_free(key);
	g_list_free(dir);

	g_return_val_if_fail(lu_files_create_backup(filename), FALSE);

	fd = open(filename, O_RDWR);
	if(fd != -1) {
		lock = lock_obtain(fd);
		if(fstat(fd, &st) != -1) {
			contents = g_malloc0(st.st_size + 1);
			if(read(fd, contents, st.st_size) == st.st_size) {
				tmp = g_strdup_printf("%s:", (char*)name->data);
				line = module->scache->cache(module->scache, tmp);
				g_free(tmp);

				if(strncmp(contents, line, strlen(line)) == 0) {
					char *p = strchr(contents, '\n');
					strcpy(contents, p ? (p + 1) : "");
				} else {
					char *p;
					tmp = g_strdup_printf("\n%s:", (char*)name->data);
					line = module->scache->cache(module->scache, tmp);
					g_free(tmp);
					if((p = strstr(contents, line)) != NULL) {
						char *q = strchr(p + 1, '\n');
						strcpy(p + 1, q ? (q + 1) : "");
					}
				}
				lseek(fd, 0, SEEK_SET);
				if(write(fd, contents, strlen(contents)) == strlen(contents)) {
					ftruncate(fd, strlen(contents));
					ret = TRUE;
				}
			}
			g_free(contents);
		}
		lock_free(fd, lock);
		close(fd);
	}
	g_free(filename);

	return ret;
}

static gboolean
lu_files_user_del(struct lu_module *module, struct lu_ent *ent)
{
	return generic_del(module, "files", "passwd", ent);
}

static gboolean
lu_files_group_del(struct lu_module *module, struct lu_ent *ent)
{
	return generic_del(module, "files", "group", ent);
}

static gboolean
lu_shadow_user_del(struct lu_module *module, struct lu_ent *ent)
{
	gboolean ret = generic_del(module, "shadow", "shadow", ent);
	if(ret) {
		lu_ent_set(ent, LU_USERPASSWORD, "x");
	}
	return ret;
}

static gboolean
lu_shadow_group_del(struct lu_module *module, struct lu_ent *ent)
{
	gboolean ret = generic_del(module, "shadow", "gshadow", ent);
	if(ret) {
		lu_ent_set(ent, LU_USERPASSWORD, "x");
	}
	return ret;
}

static char *
lock_process(const char *cryptedPassword, gboolean lock, struct lu_ent *ent)
{
	char *ret = NULL;
	if(strncmp(cryptedPassword, "{crypt}", 7) == 0) {
		if(lock) {
			if(cryptedPassword[7] != '!') {
				cryptedPassword = g_strconcat("{crypt}!",
							      cryptedPassword + 7,
							      NULL);
				ret = ent->vcache->cache(ent->vcache, cryptedPassword);
				g_free((char*)cryptedPassword);
			}
		} else {
			if(cryptedPassword[7] == '!') {
				cryptedPassword = g_strconcat("{crypt}",
							      cryptedPassword +
							      8,
							      NULL);
				ret = ent->vcache->cache(ent->vcache,
							 cryptedPassword);
				g_free((char*)cryptedPassword);
			}
		}
	} 
	return ret;
}

static gboolean
generic_lock(struct lu_module *module, const char *module_name,
	     const char *base_name, struct lu_ent *ent,
	     format_fn formatter, gboolean lock)
{
	gboolean ret = FALSE;
	struct lu_ent *tmp = NULL;
	GList *i = NULL, *add_list = NULL, *remove_list = NULL;
	char *cryptedPassword = NULL;

	tmp = lu_ent_new();
	lu_ent_copy(ent, tmp);

	for(i = lu_ent_get(tmp, LU_USERPASSWORD); i; i = g_list_next(i)) {
		if(i->data) {
			if(strncmp(i->data, "{crypt}", 7) == 0) {
				cryptedPassword = lock_process((char*)i->data,
							       lock, ent);
				if(cryptedPassword) {
					remove_list = g_list_append(remove_list,
								    i->data);
					add_list = g_list_append(add_list,
								 cryptedPassword);
				}
			}
		}
	}
	for(i = remove_list; i; i = g_list_next(i)) {
		lu_ent_del(tmp, LU_USERPASSWORD, i->data);
	}
	for(i = add_list; i; i = g_list_next(i)) {
		lu_ent_add_original(tmp, LU_USERPASSWORD, i->data);
	}

	if(g_list_length(add_list) > 0) {
		ret = generic_mod(module, module_name, base_name,
				  formatter, tmp);
	}

	g_list_free(add_list);
	g_list_free(remove_list);

	lu_ent_free(tmp);

	return ret;
}

static gboolean
lu_files_user_lock(struct lu_module *module, struct lu_ent *ent)
{
	return generic_lock(module, "files", "passwd", ent,
			    lu_files_format_user, TRUE);
}

static gboolean
lu_files_user_unlock(struct lu_module *module, struct lu_ent *ent)
{
	return generic_lock(module, "files", "passwd", ent,
			    lu_files_format_user, FALSE);
}

static gboolean
lu_files_group_lock(struct lu_module *module, struct lu_ent *ent)
{
	return generic_lock(module, "files", "group", ent,
			    lu_files_format_group, TRUE);
}

static gboolean
lu_files_group_unlock(struct lu_module *module, struct lu_ent *ent)
{
	return generic_lock(module, "files", "group", ent,
			    lu_files_format_group, FALSE);
}

static gboolean
lu_shadow_user_lock(struct lu_module *module, struct lu_ent *ent)
{
	return generic_lock(module, "shadow", "shadow", ent,
			    lu_shadow_format_user, TRUE);
}

static gboolean
lu_shadow_user_unlock(struct lu_module *module, struct lu_ent *ent)
{
	return generic_lock(module, "shadow", "shadow", ent,
			    lu_shadow_format_user, FALSE);
}

static gboolean
lu_shadow_group_lock(struct lu_module *module, struct lu_ent *ent)
{
	return generic_lock(module, "shadow", "gshadow", ent,
			    lu_shadow_format_group, TRUE);
}

static gboolean
lu_shadow_group_unlock(struct lu_module *module, struct lu_ent *ent)
{
	return generic_lock(module, "shadow", "gshadow", ent,
			    lu_shadow_format_group, FALSE);
}

static gboolean
close_module(struct lu_module *module)
{
	g_return_val_if_fail(module != NULL, FALSE);

	module->scache->free(module->scache);
	memset(module, 0, sizeof(struct lu_module));
	g_free(module);
	return TRUE;
}

struct lu_module *
lu_files_init(struct lu_context *context)
{
	struct lu_module *ret = NULL;

	g_return_val_if_fail(context != NULL, FALSE);

	/* Handle authenticating to the data source. */
#ifndef DEBUG
	if(geteuid() != 0) {
		g_warning(_("Not executing with superuser privileges."));
		return NULL;
	}
#endif

	/* Allocate the method structure. */
	ret = g_malloc0(sizeof(struct lu_module));
	ret->version = LU_MODULE_VERSION;
	ret->scache = lu_string_cache_new(TRUE);
	ret->name = ret->scache->cache(ret->scache, "files");

	/* Set the method pointers. */
	ret->user_lookup_name = lu_files_user_lookup_name;
	ret->user_lookup_id = lu_files_user_lookup_id;

	ret->user_add = lu_files_user_add;
	ret->user_mod = lu_files_user_mod;
	ret->user_del = lu_files_user_del;
	ret->user_lock = lu_files_user_lock;
	ret->user_unlock = lu_files_user_unlock;

	ret->group_lookup_name = lu_files_group_lookup_name;
	ret->group_lookup_id = lu_files_group_lookup_id;

	ret->group_add = lu_files_group_add;
	ret->group_mod = lu_files_group_mod;
	ret->group_del = lu_files_group_del;
	ret->group_lock = lu_files_group_lock;
	ret->group_unlock = lu_files_group_unlock;

	ret->close = close_module;

	/* Done. */
	return ret;
}

struct lu_module *
lu_shadow_init(struct lu_context *context)
{
	struct lu_module *ret = NULL;

	g_return_val_if_fail(context != NULL, NULL);

	/* Handle authenticating to the data source. */
#ifndef DEBUG
	if(geteuid() != 0) {
		g_warning(_("Not executing with superuser privileges."));
		return NULL;
	}
#endif

	/* Allocate the method structure. */
	ret = g_malloc0(sizeof(struct lu_module));
	ret->version = LU_MODULE_VERSION;
	ret->scache = lu_string_cache_new(TRUE);
	ret->name = ret->scache->cache(ret->scache, "shadow");

	/* Set the method pointers. */
	ret->user_lookup_name = lu_shadow_user_lookup_name;
	ret->user_lookup_id = lu_shadow_user_lookup_id;

	ret->user_add = lu_shadow_user_add;
	ret->user_mod = lu_shadow_user_mod;
	ret->user_del = lu_shadow_user_del;
	ret->user_lock = lu_shadow_user_lock;
	ret->user_unlock = lu_shadow_user_unlock;

	ret->group_lookup_name = lu_shadow_group_lookup_name;
	ret->group_lookup_id = lu_shadow_group_lookup_id;

	ret->group_add = lu_shadow_group_add;
	ret->group_mod = lu_shadow_group_mod;
	ret->group_del = lu_shadow_group_del;
	ret->group_lock = lu_shadow_group_lock;
	ret->group_unlock = lu_shadow_group_unlock;

	ret->close = close_module;

	/* Done. */
	return ret;
}
