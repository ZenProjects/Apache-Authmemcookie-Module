AuthMemCookie Apache Module
=============

The "Auth MemCookie" is an Apache v2.0 Authentication and authorization modules are based on "cookie" Authentication mechanism.

The module doesn’t make Authentication by it self, but verify if Authentication "the cookie" is valid for each url protected by the module. The module validate also if the "authenticated user" have authorization to access url.

Authentication is made externally by an Authentication html form page and all Authentication information necessary to the module a stored in memcached identified by the cookie value "Authentication session id" by this login page.

- All the documentation are [here](http://zenprojects.github.io/Apache-Authmemcookie-Module/)
- And the old original documentation are [here](http://htmlpreview.github.io/?https://github.com/ZenProjects/Apache-Authmemcookie-Module/blob/master/docs/readme.html)


# Build dependency

You must have compiled and installed:

- [libevent](http://libevent.org/) use by [memcached](http://memcached.org/).

- [memcached](http://memcached.org/) the cache daemon it self.

- [libmemcached](http://libmemcached.org/) the C client API needed to compile the Apache Module.

# How to build

```
# ./configure --with-apxs=/path/to/apache/httpd/bin/apxs --with-libmemcached=/path/to/libmemcached/
# make
# make install
```

# News in this version (v1.2)

* migration from old [libmemcache](https://github.com/richp10/libmemcache-1.4.0.rc2-patched) to modern [libmemcached](http://libmemcached.org/)

# News in this version (v1.1.1)

* Correct handling of "=" in value of the memcache session (E. Dumas).
* Don't breaks basic authentication (Steve Gaarder)
* multi users/groups require support
* no more memory leak when mc_aget2 return NULL
* apache 2.4 partial support (no use the new security model)
* some portability issue (apr_strtok in place of strtok, and variable definition in front of function)
