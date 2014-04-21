GLOBUS_LOCATION=/usr


INCLUDES=-I$(GLOBUS_LOCATION)/include/globus/ -I$(GLOBUS_LOCATION)/include/globus/gcc64dbg -I/usr/lib64/globus/include/
CFLAGS=-DLDAP_DEPRECATED $(INCLUDES) -fPIC -ggdb3
LDFLAGS=-L$(GLOBUS_LOCATION)/lib64
LDLIBS=-lglobus_gssapi_gsi -lldap -lpam

all:: libgridmap_callout

libgridmap_callout::	gridmap_callout.o
	$(CC) -shared gridmap_callout.o -o libgridmap_callout.so $(LDFLAGS) $(LDLIBS)

clean::
	rm -f gridmap_callout.o

clobber:: clean
	rm -f libgridmap_callout.so
