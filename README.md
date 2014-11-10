AuthMemCookie Apache Module
=============

The "Auth MemCookie" is an Apache v2.0 Authentication and authorization modules are based on "cookie" Authentication mechanism.

The module doesn’t make Authentication by it self, but verify if Authentication "the cookie" is valid for each url protected by the module. The module validate also if the "authenticated user" have authorization to access url.

Authentication is made externally by an Authentication html form page and all Authentication information necessary to the module a stored in memcached identified by the cookie value "Authentication session id" by this login page.


# Build dependency

You must have compiled and installed:

- [libevent](http://libevent.org/) use by [memcached](http://memcached.org/).

- [memcached](http://memcached.org/) the cache daemon it self.

- [libmemcache](https://github.com/richp10/libmemcache-1.4.0.rc2-patched) the C client API needed to compile the Apache Module.

# Compilation

You must modify Makefile:

- Set correctly the MY_APXS variable to point to the apache "apxs" scripts.

- Add the memcache library path in MY_LDFLAGS variable if necessary (-L<my memcache lib path>)

How to compile:

```
# make
# make install
```

After that the "mod_auth_memcookie.so" is generated in apache "modules" directory.

#Documentation

All the documentation are here: http://authmemcookie.sourceforge.net/

# Fork

https://github.com/openSUSE/apache2-mod_auth_memcookie

https://github.com/richp10/apache2-mod_auth_memcookie-1.0.3
