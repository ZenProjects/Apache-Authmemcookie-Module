AC_DEFUN([APACHE_WITH],[

  AC_ARG_WITH(
    apxs,
    [  --with-apxs[=EXE]         Apache2 apxs script],
    ,
    [with_apxs="no"]
  )

  AC_MSG_CHECKING(for Apache apxs script)

  if test "$with_apxs" = "no"; then
    AC_MSG_ERROR( Specify where is the apache apxs script using --with-apxs)
  else
    AP_INCLUDE_DIR=$($with_apxs -q "includedir")
    # make sure that a well known include file exists
    if test -e $AP_INCLUDE_DIR/httpd.h; then
      AC_MSG_RESULT( found!)
    else
      AC_MSG_ERROR( $with_apxs not found. )
    fi
    APXS=$with_apxs
  fi

  AC_SUBST(APXS) 

])


