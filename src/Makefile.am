AUTOMAKE_OPTIONS = foreign subdir-objects

AM_CPPFLAGS = -D_GNU_SOURCE \
    -I$(top_srcdir)/include \
    $(LIBNETIFYD_CFLAGS)

if BUILD_PACKAGE
lib_LTLIBRARIES = netify-plugin-fwa.la
netify_plugin_fwa_la_CPPFLAGS = $(AM_CPPFLAGS) $(LIBNFTABLES_CFLAGS)
netify_plugin_fwa_la_SOURCES = nfwa-plugin.cpp
netify_plugin_fwa_la_LDFLAGS = -module -avoid-version -shared
netify_plugin_fwa_la_LIBADD = $(LIBNETIFYD_LIBS) $(LIBNFTABLES_LIBS) -luci
endif
