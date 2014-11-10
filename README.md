AuthMemCookie Apache Module
=============

The "Auth MemCookie" is an Apache v2.0 Authentication and authorization modules are based on "cookie" Authentication mechanism.

The module doesn’t make Authentication by it self, but verify if Authentication "the cookie" is valid for each url protected by the module. The module validate also if the "authenticated user" have authorization to access url.

Authentication is made externally by an Authentication html form page and all Authentication information necessary to the module a stored in memcached identified by the cookie value "Authentication session id" by this login page.

# News in this version (v1.1)

* Correct handling of "=" in value of the memcache session (E. Dumas).
* Don't breaks basic authentication (Steve Gaarder)
* multi users/groups require support
* no more memory leak when mc_aget2 return NULL
* apache 2.4 partial support (no use the new security model)
* some portability issue (apr_strtok in place of strtok, and variable definition in front of function)

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

* this fork seam to  done by opensuse team
* ported the code to libmemcached.
* made sure that the session data contains no \r or \n.
* made sure that the cookie is a valid md5sum.
* added Auth_memCookie_SessionHeaders option to specify which headers should be cleared from the input headers and taken from the session data.
* added szAuth_memCookie_AuthentificationURI to configure that the session is created by doing a subrequest to the specfied
* URI and using the returned headers (uses the configured SessionHeaders).
* added Auth_memCookie_AuthentificationHeader option to tell the module that it can take the user name from the specified header when it creates the session.
* added Auth_memCookie_AuthentificationURIOnlyAuth to make it * just run the authentification steps for the subrequest (data is taken from the input headers in that case).
* added Auth_memCookie_CookieDomain to specify a domain for the session cookie.
* added Auth_memCookie_AllowAnonymous to specify that no session is required for the request.
* added Auth_memCookie_CommandHeader to specify a way to issue commands for session managemant: "login" makes it ignore the AllowAnonymous flag, "logout" deletes the session. 

https://github.com/richp10/apache2-mod_auth_memcookie-1.0.3

- apache 2.4
- PAtched version of libmemcached that fixes Apache error: undefined symbol: mcm_buf_len

http://search.cpan.org/~piers/Apache-Auth-AuthMemCookie-0.02/lib/Apache/Auth/AuthMemCookie.pm

- perl version !
