SUBDIRS = compat

AUTOMAKE_OPTIONS = foreign 1.7

# Our main program
bin_PROGRAMS = proxy_bio_unittest tlsdate-routeup tlsdate tlsdate-helper \
               tlsdated tlsdated_unittest
AM_CFLAGS = -fvisibility=hidden
proxy_bio_unittest_SOURCES = proxy-bio.c proxy-bio-unittest.c test-bio.c util.c
proxy_bio_unittest_LDADD = -lssl -lcrypto
tlsdate_routeup_SOURCES = routeup.c util.c
tlsdate_routeup_CPPFLAGS = -DROUTEUP_MAIN
tlsdate_SOURCES = tlsdate.c
tlsdate_helper_SOURCES = proxy-bio.c util.c tlsdate-helper.c
tlsdate_helper_LDADD = -lssl -lcrypto -lrt \
                       $(top_builddir)/src/compat/libtlsdate_compat.la
tlsdated_SOURCES = routeup.c tlsdate-monitor.c tlsdated.c util.c \
                   tlsdate-setter.c \
                   events/check_continuity.c events/kickoff_time_sync.c \
                   events/route_up.c events/run_tlsdate.c events/sigterm.c \
                   events/save.c events/time_set.c events/tlsdate_status.c \
                   events/sigchld.c
if HAVE_SECCOMP_FILTER
tlsdated_SOURCES += seccomp.c
endif
if HAVE_DBUS
tlsdated_SOURCES += dbus.c
endif
tlsdated_CPPFLAGS = -DTLSDATED_MAIN

tlsdated_unittest_SOURCES = $(tlsdated_SOURCES) tlsdated-unittest.c

TESTS = proxy_bio_unittest tlsdated_unittest

# We're not shipping headers
noinst_HEADERS = tlsdate.h
