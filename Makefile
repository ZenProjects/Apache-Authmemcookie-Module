MY_APXS=/usr/sbin/apxs2
MY_LDFLAGS=-lmemcache -L/mnt/distributions/rpmbuilds/ste-1.0/ste-php/TMP/SFR-libmemcache-1.4.0.rc2-build/product/sfr-suse-addon/lib
MY_CFLAGS=-I/mnt/distributions/rpmbuilds/ste-1.0/ste-php/TMP/SFR-libmemcache-1.4.0.rc2-build/product/sfr-suse-addon/include

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

