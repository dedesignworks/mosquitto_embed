# Makefile for building the NIF
#
# Makefile targets:
#
# all/install   build and install the NIF
# clean         clean build products and intermediates
#
# Variables to override:
#
# BUILD         where to store intermediate files (defaults to src directory)
# PREFIX        path to the installation direction (defaults to ./priv)
#
# CC            C compiler
# CROSSCOMPILE	crosscompiler prefix, if any
# CFLAGS	compiler flags for compiling all C files
# ERL_CFLAGS	additional compiler flags for files using Erlang header files
# ERL_EI_INCLUDE_DIR include path to ei.h (Required for crosscompile)
# ERL_EI_LIBDIR path to libei.a (Required for crosscompile)
# LDFLAGS	linker flags for linking all binaries
# ERL_LDFLAGS	additional linker flags for projects referencing Erlang libraries
# MIX_APP_PATH  path to the build directory
include src/config.mk

MOSQUITTO_DIR=$(MIX_DEPS_PATH)/mosquitto
MOSQUITTOD_SRC=$(MOSQUITTO_DIR)/src
DIRS=${MOSQUITTOD_SRC}

PREFIX = $(MIX_APP_PATH)/priv
BUILD  = $(MIX_APP_PATH)/obj

CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter
CFLAGS += -std=c99 -D_GNU_SOURCE -fPIC 

CPPFLAGS += -fPIC

# Mosquitto handles the cross compile variables differently than Nerves
override undefine CROSS_COMPILE

###################
# If you're having trouble, commenting in the following line
# may give some more hints.  Be sure to rebuild everything by invoking
# "mix clean" and then "mix compile", so that the flag takes effect.
#CFLAGS += -DDEBUG

SRC=$(wildcard src/*.c)

# Windows-specific updates
ifeq ($(OS),Windows_NT)

# Libraries needed to enumerate serial ports
LDFLAGS += -lSetupapi -lCfgmgr32

# On Windows, make defaults CC=cc and
# cc doesn't exist with mingw
ifeq ($(CC),cc)
CC = gcc
endif

# Statically link on Windows to simplify distribution of pre-built version
LDFLAGS += -static

# To avoid linking issues, use copy/pasted version of ei.
# YES, this is unfortunate, but it was easier than
# battling mingw/visual c++ differences.
ERL_CFLAGS = -I"$(CURDIR)/src/ei_copy"
SRC += $(wildcard src/ei_copy/*.c)
CFLAGS += -DUNICODE

LIBEXT=.dll

RM=del

else
# Non-Windows

# -lrt is needed for clock_gettime() on linux with glibc before version 2.17
# (for example raspbian wheezy)
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  LDFLAGS += -lrt
endif

LIBEXT=.so

# The paths to the EI library and header files are either passed in when
# compiled by Nerves (crosscompiled builds) or determined by mix.exs for
# host builds.
ifeq ($(ERL_EI_INCLUDE_DIR),)
$(error ERL_EI_INCLUDE_DIR not set. Invoke via mix)
endif
ifeq ($(ERL_EI_LIBDIR),)
$(error ERL_EI_LIBDIR not set. Invoke via mix)
endif

# Set Erlang-specific compile and linker flags
ERL_CFLAGS ?= -I$(ERL_EI_INCLUDE_DIR)
ERL_LDFLAGS ?= -L$(ERL_EI_LIBDIR) -lei

# If compiling on OSX and not crosscompiling, include CoreFoundation and IOKit
ifeq ($(CROSSCOMPILE),)
ifeq ($(shell uname),Darwin)
LDFLAGS += -framework CoreFoundation -framework IOKit
endif
endif

endif


MOSQUITTOD_OBJS=	\
		${MOSQUITTOD_SRC}/alias_mosq.o \
		${MOSQUITTOD_SRC}/bridge.o \
		${MOSQUITTOD_SRC}/conf.o \
		${MOSQUITTOD_SRC}/conf_includedir.o \
		${MOSQUITTOD_SRC}/context.o \
		${MOSQUITTOD_SRC}/database.o \
		${MOSQUITTOD_SRC}/handle_auth.o \
		${MOSQUITTOD_SRC}/handle_connack.o \
		${MOSQUITTOD_SRC}/handle_connect.o \
		${MOSQUITTOD_SRC}/handle_disconnect.o \
		${MOSQUITTOD_SRC}/handle_ping.o \
		${MOSQUITTOD_SRC}/handle_pubackcomp.o \
		${MOSQUITTOD_SRC}/handle_publish.o \
		${MOSQUITTOD_SRC}/handle_pubrec.o \
		${MOSQUITTOD_SRC}/handle_pubrel.o \
		${MOSQUITTOD_SRC}/handle_suback.o \
		${MOSQUITTOD_SRC}/handle_subscribe.o \
		${MOSQUITTOD_SRC}/handle_unsuback.o \
		${MOSQUITTOD_SRC}/handle_unsubscribe.o \
		${MOSQUITTOD_SRC}/logging.o \
		${MOSQUITTOD_SRC}/loop.o \
		${MOSQUITTOD_SRC}/memory_mosq.o \
		${MOSQUITTOD_SRC}/misc_mosq.o \
		${MOSQUITTOD_SRC}/net.o \
		${MOSQUITTOD_SRC}/net_mosq.o \
		${MOSQUITTOD_SRC}/net_mosq_ocsp.o \
		${MOSQUITTOD_SRC}/packet_datatypes.o \
		${MOSQUITTOD_SRC}/packet_mosq.o \
		${MOSQUITTOD_SRC}/property_broker.o \
		${MOSQUITTOD_SRC}/property_mosq.o \
		${MOSQUITTOD_SRC}/persist_read.o \
		${MOSQUITTOD_SRC}/persist_read_v234.o \
		${MOSQUITTOD_SRC}/persist_read_v5.o \
		${MOSQUITTOD_SRC}/persist_write.o \
		${MOSQUITTOD_SRC}/persist_write_v5.o \
		${MOSQUITTOD_SRC}/plugin.o \
		${MOSQUITTOD_SRC}/read_handle.o \
		${MOSQUITTOD_SRC}/security.o \
		${MOSQUITTOD_SRC}/security_default.o \
		${MOSQUITTOD_SRC}/send_auth.o \
		${MOSQUITTOD_SRC}/send_connack.o \
		${MOSQUITTOD_SRC}/send_connect.o \
		${MOSQUITTOD_SRC}/send_disconnect.o \
		${MOSQUITTOD_SRC}/send_mosq.o \
		${MOSQUITTOD_SRC}/send_publish.o \
		${MOSQUITTOD_SRC}/send_suback.o \
		${MOSQUITTOD_SRC}/send_subscribe.o \
		${MOSQUITTOD_SRC}/send_unsuback.o \
		${MOSQUITTOD_SRC}/send_unsubscribe.o \
		${MOSQUITTOD_SRC}/service.o \
		${MOSQUITTOD_SRC}/session_expiry.o \
		${MOSQUITTOD_SRC}/signals.o \
		${MOSQUITTOD_SRC}/subs.o \
		${MOSQUITTOD_SRC}/sys_tree.o \
		${MOSQUITTOD_SRC}/time_mosq.o \
		${MOSQUITTOD_SRC}/tls_mosq.o \
		${MOSQUITTOD_SRC}/utf8_mosq.o \
		${MOSQUITTOD_SRC}/util_mosq.o \
		${MOSQUITTOD_SRC}/util_topic.o \
		${MOSQUITTOD_SRC}/websockets.o \
		${MOSQUITTOD_SRC}/will_delay.o \
		${MOSQUITTOD_SRC}/will_mosq.o

HEADERS =$(wildcard src/*.h)
OBJ=$(SRC:src/%.c=$(BUILD)/%.o)
PORTLIB=$(PREFIX)/mosquitto_embed$(LIBEXT)
MOSQ_INC=-I"$(MOSQUITTO_DIR)/src" -I"$(MOSQUITTO_DIR)" -I"$(MOSQUITTO_DIR)/lib" -I"$(MOSQUITTO_DIR)/src/deps"
all: install

install: $(PREFIX) $(BUILD) mosquitto $(PORTLIB)

$(OBJ): $(HEADERS) src/Makefile

$(BUILD)/%.o: src/%.c
	$(CC) -c $(ERL_CFLAGS) $(CFLAGS) -o $@ $<

$(BUILD)/mosquitto_embed.o: src/mosquitto_embed.c
	$(CC) -c $(ERL_CFLAGS) $(CFLAGS) $(MOSQ_INC) -o $@ $<

$(BUILD)/mosquitto_main.o : src/mosquitto_main.c $(MOSQUITTO_DIR)/src/mosquitto_broker_internal.h
	${CC} $(BROKER_CPPFLAGS) $(BROKER_CFLAGS) $(MOSQ_INC) -c $< -o $@

# ${CROSS_COMPILE}$(CC) -shared $(LIB_LDFLAGS) $^ -o $@ ${LIB_LIBADD}
$(PORTLIB): $(OBJ) $(MOSQUITTOD_OBJS)
	$(CC) -fpic -shared $^ $(ERL_LDFLAGS) $(LDFLAGS) ${BROKER_LDFLAGS} -o $@ $(BROKER_LDADD)

ifeq ($(OS),Windows_NT)
$(PREFIX) $(BUILD) $(BUILD)/ei_copy:
	mkdir $(subst /,\\,$@)

clean:
	-$(RM) $(subst /,\,$(PORTLIB) $(OBJ))
else
$(PREFIX) $(BUILD) $(BUILD)/ei_copy:
	mkdir -p $@

clean:
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} clean; done
	$(RM) $(PORTLIB) $(OBJ)
endif

reallyclean : clean
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} reallyclean; done

sync_config:
	cp -f src/config.mk $(MOSQUITTO_DIR)/config.mk

mosquitto: sync_config
ifeq ($(UNAME),Darwin)
	$(error Please compile using CMake on Mac OS X)
endif
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d}; done

.PHONY: all clean install sync_config mosquitto