include ../config-plugin.mak
include $(SRC_PATH)/$(TARGET_DIR)/config-target.mak
include $(SRC_PATH)/config-host.mak

DEFINES=-I. -I.. -I$(SRC_PATH) -I$(SRC_PATH)/fpu -I$(SRC_PATH)/shared -I$(SRC_PATH)/target-$(TARGET_ARCH) -I$(SRC_PATH)/$(TARGET_DIR) -I$(SRC_PATH)/slirp
DEFINES+=-I$(GLIB_CFLAGS)

CC = gcc
CPP = g++
CFLAGS=-Wall -O2 -g -fPIC -D_GNU_SOURCE
LDFLAGS=-ldl -shared -g

GROUP_PLUGINS=group_alloc.so group_process.so group_network.so

PROJECT_PLUGINS=

TRACE_LIBS=-L../ -l$(PLUGIN_NAME)

all: group_hooks project_hooks

%.o: %.c
	$(CC) $(CFLAGS) $(DEFINES) -c -o $@ $<

%.o: %.cpp
	$(CPP) $(CFLAGS) $(DEFINES) -c -o $@ $<

group_hooks: $(GROUP_PLUGINS)

project_hooks : $(PROJECT_PLUGINS)

$(GROUP_PLUGINS): %.so: %.o group_hook_helper.o
	$(CC) $(LDFLAGS) $^ -o $@ $(TRACE_LIBS)

$(PROJECT_PLUGINS): %.so: %.o group_hook_helper.o
	$(CC) $(LDFLAGS) $^ -o $@ $(TRACE_LIBS)

clean:
	rm -f *.o *.so *~

