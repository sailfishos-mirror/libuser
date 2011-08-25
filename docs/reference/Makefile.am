# FIXME: remove this workaround after bugzilla.gnome.org #657377 is fixed
setup-build-workaround.stamp:
	-@if test "$(abs_srcdir)" != "$(abs_builddir)" ; then \
	   echo 'WORKAROUND: Preparing build'; \
	   test -d $(abs_srcdir)/tmpl && \
	       { cp -r $(abs_srcdir)/tmpl $(abs_builddir)/; \
		 chmod -R u+w $(abs_builddir)/tmpl; } \
	fi
	@touch setup-build.stamp

setup.stamp: setup-build-workaround.stamp

# Note that there is another workaround at the bottom of this file!

## Process this file with automake to produce Makefile.in

# This is a blank Makefile.am for using gtk-doc.
# Copy this to your project's API docs directory and modify the variables to
# suit your project. See the GTK+ Makefiles in gtk+/docs/reference for examples
# of using the various options.

# The name of the module, e.g. 'glib'.
DOC_MODULE=libuser

# The top-level SGML file. Change it if you want.
DOC_MAIN_SGML_FILE=$(DOC_MODULE)-docs.sgml

# The directory containing the source code. Relative to $(srcdir).
# gtk-doc will search all .c & .h files beneath here for inline comments
# documenting functions and macros.
DOC_SOURCE_DIR=$(abs_top_srcdir)/lib

# Extra options to supply to gtkdoc-scan.
SCAN_OPTIONS=

# Extra options to supply to gtkdoc-mkdb.
MKDB_OPTIONS=

# Extra options to supply to gtkdoc-fixref.
FIXXREF_OPTIONS=

# Used for dependencies.
HFILE_GLOB=
CFILE_GLOB=

# Header files to ignore when scanning.
IGNORE_HFILES=internal.h user_private.h

# Images to copy into HTML directory.
HTML_IMAGES =

# Extra SGML files that are included by $(DOC_MAIN_SGML_FILE).
content_files =

# Other files to distribute.
extra_files =

# CFLAGS and LDFLAGS for compiling scan program. Only needed if your app/lib
# contains GtkObjects/GObjects and you want to document signals and properties.
GTKDOC_CFLAGS =
GTKDOC_LIBS =

# If you need to override some of the declarations, place them in this file
# and uncomment this line.
DOC_OVERRIDES = $(DOC_MODULE)-overrides.txt

include $(srcdir)/gtk-doc.make

# FIXME: remove this workaround after updating to gtk-doc >= 1.18
# This code is based on git version of dist-hook in gtk-doc.make
dist-hook: dist-check-gtkdoc dist-hook-local
	@mkdir $(distdir)/tmpl
	@mkdir $(distdir)/html
	@-cp ./tmpl/*.sgml $(distdir)/tmpl
	@cp ./html/* $(distdir)/html
	@-cp ./$(DOC_MODULE).pdf $(distdir)/
	@-cp ./$(DOC_MODULE).types $(distdir)/
	@-cp ./$(DOC_MODULE)-sections.txt $(distdir)/
	@cd $(distdir) && rm -f $(DISTCLEANFILES)
	@$(GTKDOC_REBASE) --online --relative --html-dir=$(distdir)/html
