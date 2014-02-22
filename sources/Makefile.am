CC = gcc
bin_PROGRAMS = arewiksd
arewiksd_SOURCES = \
		arewik.c \
		buffer.c \
		compression.c \
		config.c \
		debug.c \
		functions.c \
		htmlstreamparser.c \
		logs.c \
		mod_esearch.c \
		mod_plain.c \
		mod_riak.c \
		mod_webhdfs.c \
		network.c \
		rotate.c \
		server.c \
		signal.c \
		thread.c
#
AM_CFLAGS = -g -zmuldefs -O3 -MMD -MP -MF -DXOPEN_SOURCE -Wall -fPIC ${LDFLAGS} ${LIBS}
