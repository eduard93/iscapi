.SUFFIXES: .c

CXX=gcc
CPCCC=$(CXX)

INSTALL_DIR=/opt/iscapi
CSP_INCLUDE=/opt/cprocsp/include
CSP_LIB=/opt/cprocsp/lib/amd64
ISC_INCLUDE=/opt/isc/ensemble/dev/cpp/include

CFLAGS=-DUNIX -DHAVE_LIMITS_H -DHAVE_STDINT_H 	-I$(CSP_INCLUDE) -I$(CSP_INCLUDE)/cpcsp \
						-I$(CSP_INCLUDE)/asn1c/rtsrc -I$(CSP_INCLUDE)/asn1data \
						-I$(ISC_INCLUDE) \
						-DSIZEOF_VOID_P=8 -fPIC -g -Wall
						

LDFLAGS= -L$(CSP_LIB) -lssp -lcapi10 -lcapi20 -lpthread -fPIC -g

# -lasn1data

#OBJS=iscapi.o

all:	clean iscapi.so install #testcapi

iscapi.so: ISCAPI/common.o ISCAPI/logger.o ISCAPI/iscapi.o
	$(CPCCC) -shared ISCAPI/common.o ISCAPI/logger.o ISCAPI/iscapi.o $(LDFLAGS) -o $@

testcapi: ISCAPI/common.o ISCAPI/logger.o ISCAPITEST/testmain.o
	$(CPCCC) ISCAPI/common.o ISCAPI/logger.o ISCAPITEST/testmain.o $(LDFLAGS) -o $@

clean:
	rm -f ISCAPI/*.o
	rm -f ISCAPITEST/*.o
	rm -f iscapi.so testcapi

install:
	cp -f iscapi.so $(INSTALL_DIR)/

ISCAPI/iscapi.o:
	$(CPCCC) $(CFLAGS) -c -o $@ ISCAPI/dllmain.c 

ISCAPITEST/testcapi.o:
	$(CPCCC) $(CFLAGS) -c -o $@ ISCAPITEST/testmain.c 


ISCAPI/common.o:
	$(CPCCC) $(CFLAGS) -c -o $@ Common/common.c

ISCAPI/logger.o:
	$(CPCCC) $(CFLAGS) -c -o $@ Common/logger.c

