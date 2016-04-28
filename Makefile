MY_APXS=/usr/sbin/apxs
MY_LDFLAGS=-lmemcache 
MY_CFLAGS=

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

