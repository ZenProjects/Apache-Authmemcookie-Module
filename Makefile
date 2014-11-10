#MY_APXS=/usr/sbin/apxs
MY_APXS=/opt/srv/httpd/bin/apxs
MY_LDFLAGS=-lmemcache -L/opt/srv/lib/libmemcache/lib/
MY_CFLAGS=-I/opt/srv/lib/libmemcache/include

.SUFFIXES: .c .o .la
.c.la:
	$(MY_APXS) $(MY_LDFLAGS) $(MY_CFLAGS) -c $< 

all:  mod_auth_memcookie.la

install: mod_auth_memcookie.la
	@echo "-"$*"-" "-"$?"-" "-"$%"-" "-"$@"-" "-"$<"-"
	$(MY_APXS) -i $?

clean:
	-rm -f *.o *.lo *.la *.slo 
	-rm -rf .libs

