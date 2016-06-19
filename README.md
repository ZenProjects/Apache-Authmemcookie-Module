AuthMemCookie Apache Module
=============

The "Auth MemCookie" is an Apache v2 Authentication and authorization modules are based on "cookie" Authentication mechanism.

The module doesn’t make Authentication by it self, but verify if Authentication "the cookie" are valid for each url protected by the module. The module validate also if the "authenticated user" have authorization to access url.

Authentication is made externally by an Authentication html form page and all Authentication information necessary to the module a stored in memcached identified by the cookie value "Authentication session id" by this login page.

# Documentation 

- All the documentation are [here](http://zenprojects.github.io/Apache-Authmemcookie-Module/)

# News in v2.0

* Full support for apache 2.3/2.4 authz/authn model support
* Fix http header not sending to backend
* Add support for setting prefix http header other than "MCAC_"
* Add public zone support (Require mcac-public only in apache 2.3/2.4)
* Http header name sended to backend in uppercase

# News in v1.2

* Migration from old [libmemcache](https://github.com/richp10/libmemcache-1.4.0.rc2-patched) to modern [libmemcached](http://libmemcached.org/)

# News in v1.1.1

* Correct handling of "=" in value of the memcache session (E. Dumas).
* Don't breaks basic authentication (Steve Gaarder)
* Multi users/groups require support
* Fix memory leak when mc_aget2 return NULL
* Apache 2.4 partial support (no use the new security model)
* Fix somme portability issue (apr_strtok in place of strtok, and variable definition in front of function)
