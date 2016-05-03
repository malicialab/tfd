include config-plugin.mak
include $(SRC_PATH)/$(TARGET_DIR)/config-target.mak
include $(SRC_PATH)/config-host.mak

#SLEUTHKIT_PATH=$(SRC_PATH)/shared/sleuthkit/
LLCONF_PATH=$(SRC_PATH)/shared/llconf/

DEFINES=-I. -I$(SRC_PATH) -I$(SRC_PATH)/plugins -I$(SRC_PATH)/fpu -I$(SRC_PATH)/shared -I$(SRC_PATH)/target-$(TARGET_ARCH) -I$(SRC_PATH)/$(TARGET_DIR) -I$(SRC_PATH)/slirp
DEFINES+=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_GNU_SOURCE -DNEED_CPU_H
DEFINES+=-I$(LLCONF_PATH)/install/include
DEFINES+=-I$(GLIB_CFLAGS)
#DEFINES+=-I$(SLEUTHKIT_PATH)/src/fstools -I$(SLEUTHKIT_PATH)/src/auxtools -I$(SLEUTHKIT_PATH)/src/imgtools -DLINUX2 -DTRACE_ENABLED

CC=gcc
CPP=g++
# CFLAGS=-Wall -O2 -g -fPIC -MMD 
# CFLAGS=-Wall -g -fPIC 
CFLAGS=-Wall -O2 -g -fPIC 
LDFLAGS=-g -shared 
#LIBS=-L$(SLEUTHKIT_PATH)/lib -lfstools -limgtools -lauxtools
#LIBS+=-L$(SLEUTHKIT_PATH)/src/afflib/lib/ -lafflib -L$(SLEUTHKIT_PATH)/src/libewf -lewf
LIBS+=$(LLCONF_PATH)/install/lib/libllconf.a

ifeq ($(ARCH), x86_64)
LIBS+=-L$(SRC_PATH)/shared/xed2/xed2-intel64/lib -lxed
DEFINES+= -I$(SRC_PATH)/shared/xed2/xed2-intel64/include
endif
ifeq ($(ARCH), i386)
LIBS+=-L$(SRC_PATH)/shared/xed2/xed2-ia32/lib -lxed
DEFINES+= -I$(SRC_PATH)/shared/xed2/xed2-ia32/include
endif

ifeq ($(TRACE_VERSION_50), y)
OBJS=trace50.o
else
OBJS=trace.o
endif

ifeq ($(STATE_VERSION_20), y)
OBJS+=state20.o
else
OBJS+=state.o
endif

OBJS+=operandinfo.o conditions.o network.o errdet.o conf.o tfd.o trackproc.o readwrite.o skiptaint.o hook_helpers.o hook_plugin_loader.o

all: tfd.so ini/main.ini ini/hook_plugin.ini

#SHARED_LIBS=$(SLEUTHKIT_PATH)/lib/libauxtools.a
#SHARED_LIBS+=$(SLEUTHKIT_PATH)/lib/libfstools.a
#SHARED_LIBS+=$(SLEUTHKIT_PATH)/lib/libimgtools.a
#SHARED_LIBS+=$(SLEUTHKIT_PATH)/src/afflib/lib/libafflib.a
#SHARED_LIBS+=$(SLEUTHKIT_PATH)/src/libewf/libewf.a
SHARED_LIBS=$(LLCONF_PATH)/src/.libs/libllconf.a

#deps:
$(SLEUTHKIT_PATH)/lib/libauxtools.a:
	./build-deps.sh $(SRC_PATH)

$(SLEUTHKIT_PATH)/lib/libfstools.a:
	./build-deps.sh $(SRC_PATH)

$(SLEUTHKIT_PATH)/lib/libimgtools.a:
	./build-deps.sh $(SRC_PATH)

$(SLEUTHKIT_PATH)/src/afflib/lib/libafflib.a:
	./build-deps.sh $(SRC_PATH)

$(SLEUTHKIT_PATH)/src/libewf/libewf.a:
	./build-deps.sh $(SRC_PATH)

$(LLCONF_PATH)/src/.libs/libllconf.a:
	./build-deps.sh $(SRC_PATH)

hooks: hook_helpers.o hooks/group_hook_helper.o hooks/group_alloc.o hooks/group_process.o hooks/group_network.o
	$(MAKE) -C ./hooks group_hooks

ini/main.ini: ini/main.ini.in
	@perl -pe 's[TFD_PATH][$(CURDIR)]g' $< >$@

ini/hook_plugin.ini: ini/hook_plugin.ini.in
	cp $< $@

%.o: %.c 
	$(CC) $(CFLAGS) $(DEFINES) -c -o $@ $<

%.o: %.cpp
	$(CPP) $(CFLAGS) $(DEFINES) -c -o $@ $<

tfd.so: $(SHARED_LIBS) $(OBJS)
	$(CPP) $(LDFLAGS) $^ -o $@ $(LIBS)
	ar cru libtfd.a $@

tfd-static.so: $(OBJS)
	$(CPP) -static-libgcc -Wl,-static $(LDFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -f *.o *.d *.so *.a *~ $(PLUGIN) 

realclean:
	rm -f *.o  *.d *.so *.a *~ $(PLUGIN) ini/main.ini ini/hook_plugin.ini

# Include automatically generated dependency files
-include $(wildcard *.d)

