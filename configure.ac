AC_INIT(configure.ac)
AM_INIT_AUTOMAKE(libuser,0.49.97)

AC_PROG_CC
AC_ISC_POSIX
AC_PROG_LN_S
AC_PATH_PROG(MAKE,make)
AC_PROG_MAKE_SET
AC_PROG_AWK

AM_PROG_LIBTOOL

AH_VERBATIM([_],[
#define _(String) gettext(String)
],[Common gettext macro.])
AH_VERBATIM([N_],[
#define N_(String) (String)
],[Common gettext macro.])
AC_DEFINE(_GNU_SOURCE,,[Use all available glibc features.])

PKG_CHECK_MODULES(GLIB,[glib-2.0 gmodule-2.0])
PKG_CHECK_MODULES(GOBJECT,[glib-2.0 gmodule-2.0 gobject-2.0])
AC_DEFINE(G_DISABLE_DEPRECATED,,[Stay away from deprecated glib functionality.])

ALL_LINGUAS="cs da de es fr is it ja ko no pt ru sl sv tr"
AM_GNU_GETTEXT([external])

AM_MAINTAINER_MODE
if test x$GCC = xyes; then
    if test x$MAINTAINER_MODE = xyes; then
	CFLAGS="$CFLAGS -Wall -Wimplicit -Wcast-align -Wpointer-arith -Wimplicit-prototypes -Wmissing-prototypes"
    else
        CFLAGS="$CFLAGS -Wall"
    fi
fi

LIBSAVE="$LIBS"
AC_CHECK_FUNC(crypt,,[AC_CHECK_LIB(crypt,crypt)])
CRYPT_LIBS="$LIBS"
LIBS="$LIBSAVE"

LIBSAVE="$LIBS"
AC_CHECK_HEADERS(security/pam_appl.h)
AC_CHECK_FUNC(pam_start,,[AC_CHECK_LIB(pam, pam_start)])
AC_CHECK_FUNC(pam_authenticate,,[AC_CHECK_LIB(pam, pam_authenticate)])
PAM_LIBS="$LIBS"
AC_CHECK_FUNC(misc_conv,,[AC_CHECK_LIB(pam_misc, misc_conv)])
PAM_MISC_LIBS="$LIBS"
LIBS="$LIBSAVE"

LIBSAVE="$LIBS"

popt=/usr
AC_ARG_WITH(popt,
[  --without-popt=DIR       Use popt headers and libraries under DIR],
[
if test x$withval != x -a x$withval != xyes ; then
	popt=$withval
fi
])

if test x$popt != xno ; then
	if test x$popt != x -a x$popt != x/usr ; then
		CFLAGS="$CFLAGS -I$popt/include"
		CPPFLAGS="$CPPFLAGS -I$popt/include"
		LIBS="$LIBS -L$popt/lib"
	fi
	AC_CHECK_HEADERS(popt.h)
	AC_CHECK_FUNC(poptGetContext,,[AC_CHECK_LIB(popt,poptGetContext)])
fi
POPT_LIBS="$LIBS"
LIBS="$LIBSAVE"

MODULES="$MODULES ${PACKAGE}_files.so"
MODULES="$MODULES ${PACKAGE}_shadow.so"

AC_ARG_WITH(ldap,
[  --with-ldap=DIR       Use OpenLDAP 2.x headers and libraries under DIR],
[
if test x$withval != x -a x$withval != xno ; then
	ldap=$withval
else
	ldap=no
fi
],ldap=no)

if test x$ldap != xno ; then
	LIBSAVE="$LIBS"
	if test x$ldap != xyes -a x$ldap != x/usr ; then
		CFLAGS="$CFLAGS -I$ldap/include"
		CPPFLAGS="$CPPFLAGS -I$ldap/include"
		LDFLAGS="$LDFLAGS -L$ldap/lib"
		if test x$ldap != x/usr ; then
			LDAP_LDADD=-L$ldap/lib
		fi
		LIBS="$LIBS $LDAP_LDADD"
	fi
	AC_CHECK_HEADERS(ldap.h)
	AC_CHECK_FUNC(ber_alloc,,[
		AC_CHECK_LIB(lber,ber_alloc,[
			     LDAP_LIBS="-llber $LDAP_LIBS"
			     LIBS="-llber $LIBS"],,[$LDFLAGS $LIBS])])
	AC_CHECK_FUNC(ldap_sasl_bind_s,,[
		AC_CHECK_LIB(ldap,ldap_sasl_bind_s,[
			     LDAP_LIBS="-lldap $LDAP_LIBS"
			     LIBS="-lldap $LIBS"],,[$LDFLAGS $LIBS])])
	AC_CHECK_FUNC(ldap_sasl_interactive_bind_s,[
	AC_CHECK_FUNC(ldap_set_option,[
	AC_CHECK_FUNC(ldap_start_tls_s,[
	AC_CHECK_FUNC(ldap_search_s,[
	AC_CHECK_FUNC(ldap_get_values,[
	AC_CHECK_FUNC(ldap_modify_ext_s,[
	AC_CHECK_FUNC(ldap_delete_ext_s,[
	MODULES="$MODULES ${PACKAGE}_ldap.so"])])])])])])])
	LIBS="$LIBSAVE"
fi

AC_ARG_WITH(sasl,
[  --with-sasl=DIR       Use Cyrus SASL headers and libraries under DIR],
[
if test x$withval != x -a x$withval != xno ; then
	sasl=$withval
else
	sasl=no
fi
],sasl=no)

if test x$sasl != xno ; then
	LIBSAVE="$LIBS"
	if test x$sasl != xyes -a x$sasl != x/usr ; then
		CFLAGS="$CFLAGS -I$sasl/include"
		CPPFLAGS="$CPPFLAGS -I$sasl/include"
		LDFLAGS="$LDFLAGS -L$sasl/lib"
		if test x$sasl != x/usr ; then
			SASL_LDADD=-L$sasl/lib
		fi
		LIBS="$LIBS $SASL_LDADD"
	fi
	AC_CHECK_HEADERS(sasl.h)
	AC_CHECK_FUNC(sasl_setpass,,[
		AC_CHECK_LIB(sasl,sasl_setpass,[
			     SASL_LIBS="-lsasl $SASL_LIBS"
			     LIBS="-lsasl $LIBS"
			     MODULES="$MODULES ${PACKAGE}_sasldb.so"]
			     ,,[$LDFLAGS $LIBS])])
	AC_CHECK_FUNCS(sasl_checkpass,,[
	AC_CHECK_LIB(sasl,sasl_checkpass,[
	AC_DEFINE(HAVE_SASL_CHECKPASS,,[if sasl_checkpass() is defined])])])
	AC_CHECK_FUNCS(sasl_user_exists,,[
	AC_CHECK_LIB(sasl,sasl_user_exists,[
	AC_DEFINE(HAVE_SASL_USER_EXISTS,,[if sasl_user_exists() is defined])])])
	LIBS="$LIBSAVE"
fi

PYTHON_VERSION=2.2
AC_ARG_WITH(python-version,
[  --with-python-version=2.2 Version of Python to build modules for],
[PYTHON_VERSION=$withval])

PYTHON_INC=/usr/include/python${PYTHON_VERSION}
AC_ARG_WITH(python-path,
[  --with-python-path=DIR Directory headers for your version of Python are in],
[PYTHON_INC=$withval])

AC_ARG_ENABLE(quota,
[  --enable-quota    Provided support for configuring quotas],
[quota=$withval],[quota=no])
if test x$quota != xno ; then
	AC_DEFINE(QUOTALIB,libuserquota.la,[quota library])
	AC_DEFINE(QUOTAMODULE,libuserquotamodule.so,[quota python module])
	AC_DEFINE(QUOTASAMPLE,quotaq,[quota sample app])
	AC_SUBST(QUOTALIB)
	AC_SUBST(QUOTAMODULE)
	AC_SUBST(QUOTASAMPLE)
else
	AC_DEFINE(QUOTALIB,[],[quota library])
	AC_DEFINE(QUOTAMODULE,[],[quota python module])
	AC_DEFINE(QUOTASAMPLE,[],[quota sample app])
	AC_SUBST(QUOTALIB)
	AC_SUBST(QUOTAMODULE)
	AC_SUBST(QUOTASAMPLE)
fi

AC_HEADER_STDC

AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T

AC_CHECK_HEADERS([fcntl.h limits.h sys/time.h unistd.h])
AC_CHECK_FUNC([__secure_getenv strstr strtol])

test "x$prefix" = xNONE && prefix=$ac_default_prefix
test "x$exec_prefix" = xNONE && exec_prefix=${prefix}

LOCALEDIR=`eval echo $datadir/locale`
AC_DEFINE_UNQUOTED(LOCALEDIR,"$LOCALEDIR",
		   [location where locale files will be installed])
MODULEDIR=`eval echo $libdir/$PACKAGE`
AC_DEFINE_UNQUOTED(MODULEDIR,"$MODULEDIR",
		   [location where modules will be installed])
AC_DEFINE_UNQUOTED(SYSCONFDIR,"$sysconfdir",
		   [location where config files will be installed])

##################################################
# Check for gtk-doc.  Inserted verbatim.
##################################################

AC_ARG_WITH(html-dir, [  --with-html-dir=PATH path to installed docs ])

if test "x$with_html_dir" = "x" ; then
  HTML_DIR='${datadir}/gtk-doc/html'
else
  HTML_DIR=$with_html_dir
fi

AC_SUBST(HTML_DIR)

AC_CHECK_PROG(GTKDOC, gtkdoc-mkdb, true, false)

gtk_doc_min_version=0.6
if $GTKDOC ; then 
    gtk_doc_version=`gtkdoc-mkdb --version`
    AC_MSG_CHECKING([gtk-doc version ($gtk_doc_version) >= $gtk_doc_min_version])
    if perl <<EOF ; then
      exit (("$gtk_doc_version" =~ /^[[0-9]]+\.[[0-9]]+$/) &&
            ("$gtk_doc_version" >= "$gtk_doc_min_version") ? 0 : 1);
EOF
      AC_MSG_RESULT(yes)
   else
      AC_MSG_RESULT(no)
      GTKDOC=false
   fi
fi

dnl Let people disable the gtk-doc stuff.
AC_ARG_ENABLE(gtk-doc, [  --enable-gtk-doc  Use gtk-doc to build documentation [default=auto]], enable_gtk_doc="$enableval", enable_gtk_doc=auto)

if test x$enable_gtk_doc = xauto ; then
  if test x$GTKDOC = xtrue ; then
    enable_gtk_doc=yes
  else
    enable_gtk_doc=no 
  fi
fi

AM_CONDITIONAL(ENABLE_GTK_DOC, test x$enable_gtk_doc = xyes)

##################################################
# End of checks for gtk-doc.
##################################################

AC_SUBST(MODULES)
AC_SUBST(CRYPT_LIBS)
AC_SUBST(KRB5_LDADD)
AC_SUBST(KRB5_LIBS)
AC_SUBST(LDAP_LDADD)
AC_SUBST(LDAP_LIBS)
AC_SUBST(PAM_LIBS)
AC_SUBST(PAM_MISC_LIBS)
AC_SUBST(POPT_LIBS)
AC_SUBST(SASL_LDADD)
AC_SUBST(SASL_LIBS)
AC_SUBST(PYTHON_VERSION)
AC_SUBST(PYTHON_INC)

if test `eval echo x$libdir` != xNONE/lib
then
	pkglibdir=`eval echo ${libdir}/${PACKAGE}`
elif test `eval echo x$exec_prefix` != xNONE
then
	pkglibdir=`eval echo ${exec_prefix}/lib/${PACKAGE}`
elif test `eval echo x$prefix` != xNONE
then
	pkglibdir=`eval echo ${prefix}/lib/${PACKAGE}`
else
	pkglibdir=`eval echo /usr/local/lib/${PACKAGE}`
fi
scdir=`eval echo $sysconfdir`
AC_SUBST(pkglibdir)
AC_SUBST(scdir)

AM_CONFIG_HEADER(config.h)

AC_OUTPUT([ m4/Makefile 
Makefile
po/Makefile.in
lib/Makefile
modules/Makefile
python/Makefile
samples/Makefile
apps/Makefile
docs/Makefile
docs/sgml/Makefile
docs/reference/Makefile
libuser.spec
libuser.conf
libuser.pc
])

$MAKE -C po -f Makefile.in Makefile
