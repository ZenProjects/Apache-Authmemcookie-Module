AC_DEFUN([LIBMEMCACHE_WITH],[

  AC_ARG_WITH(
    libmemcache,
    [  --with-libmemcache[=DIR]  libmemcache directory - https://people.freebsd.org/~seanc/libmemcache/],
    ,
    [with_libmemcache="no"]
  )

  AC_MSG_CHECKING(for libmemcache library)

  if test "$with_libmemcache" = "no"; then
    AC_MSG_ERROR( Specify where is the libmemcache directory using --with-libmemcache)
  else
    LIBMEMCACHE_INCLUDE_DIR=$with_libmemcache/include
    LIBMEMCACHE_LIB_DIR=$with_libmemcache/lib
    # make sure that a well known include file exists
    if test -e $LIBMEMCACHE_INCLUDE_DIR/memcache.h && test -d $LIBMEMCACHE_LIB_DIR; then
      AC_MSG_RESULT( found!)
    else
      AC_MSG_ERROR( $with_libmemcache not found. )
    fi
    LIBMEMCACHE_DIR=$with_libmemcache
  fi
  AC_SUBST(LIBMEMCACHE_DIR) 

])


