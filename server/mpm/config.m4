AC_MSG_CHECKING(which MPM to use)
AC_ARG_WITH(mpm,
[  --with-mpm=MPM          Choose the process model for Apache to use.
                          MPM={dexter,mpmt_beos,mpmt_pthread,prefork,spmt_os2}],[
  APACHE_MPM=$withval
],[
  APACHE_MPM=mpmt_pthread
  PLAT=`$ac_config_guess`
  PLAT=`$ac_config_sub $PLAT`
  case "$PLAT" in
    *beos*)
      APACHE_MPM=mpmt_beos;;
    *os2_emx*)
      APACHE_MPM=spmt_os2;;
  esac 
])
AC_MSG_RESULT($APACHE_MPM)

apache_cv_mpm=$APACHE_MPM
	
if test "$apache_cv_mpm" = "mpmt_pthread" -o "$apache_cv_mpm" = "dexter"; then
  PTHREADS_CHECK
  AC_MSG_CHECKING([for which threading library to use])
  AC_MSG_RESULT($threads_result)

  if test "$pthreads_working" = "no"; then
    AC_MSG_RESULT(The currently selected MPM requires pthreads which your system seems to lack)
    AC_MSG_CHECKING(checking for replacement)
    AC_MSG_RESULT(prefork selected)
    apache_cv_mpm=prefork
  fi
fi

APACHE_CHECK_SIGWAIT_ONE_ARG

APACHE_FAST_OUTPUT(modules/mpm/Makefile)

MPM_NAME=$apache_cv_mpm
MPM_DIR=modules/mpm/$MPM_NAME
MPM_LIB=$MPM_DIR/lib${MPM_NAME}.la

APACHE_SUBST(MPM_NAME)
MODLIST="$MODLIST mpm_${MPM_NAME}"

dnl Check for pthreads and attempt to support it
AC_DEFUN(APACHE_MPM_PTHREAD, [
  if test "$pthreads_working" != "yes"; then
    AC_MSG_ERROR(This MPM requires pthreads. Try --with-mpm=prefork.)
  fi

  dnl User threads libraries need pthread.h included everywhere
  AC_DEFINE(PTHREAD_EVERYWHERE,,
    [Define if all code should have #include <pthread.h>])
])
