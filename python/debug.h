#ifndef debug_h
#define debug_h

#include <glib.h>

#define FIXME fprintf(stderr, "Function %s not implemented.\n", __FUNCTION__); \
return NULL;

#undef  DEBUG_BINDING
#ifdef  DEBUG
#define DEBUG_BINDING
#endif

#ifdef DEBUG_BINDING
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

#endif
