AC_DEFUN([LIBMEMCACHED_WITH],[

  AC_ARG_WITH(
    libmemcached,
    [  --with-libmemcached[=DIR]  libmemcached directory - http://libmemcached.org/],
    ,
    [with_libmemcached="no"]
  )

  AC_MSG_CHECKING(for libmemcached library)

  if test "$with_libmemcached" = "no"; then
    AC_MSG_ERROR( Specify where is the libmemcached directory using --with-libmemcached)
  else
    ARCH=$(uname -m)
    LONG_BIT=$(getconf LONG_BIT)
    LIBDIR=lib
    if test "$LONG_BIT" -eq 64; then 
      if test -d $with_libmemcached/lib64; then
        LIBDIR=lib64
      fi
    fi
    LIBMEMCACHED_INCLUDE_DIR=$with_libmemcached/include
    LIBMEMCACHED_LIB_DIR=$with_libmemcached/$LIBDIR
    # make sure that a well known include file exists
    if test -e $LIBMEMCACHED_INCLUDE_DIR/libmemcached-1.0/memcached.h && test -d $LIBMEMCACHED_LIB_DIR; then
      AC_MSG_RESULT( found!)
    else
      AC_MSG_ERROR( $with_libmemcached not found. )
    fi
    LIBMEMCACHED_DIR=$with_libmemcached
  fi
  AC_SUBST(LIBMEMCACHED_DIR) 
  AC_SUBST(LIBMEMCACHED_INCLUDE_DIR) 
  AC_SUBST(LIBMEMCACHED_LIB_DIR) 

])


