dnl ## XXX - Need a more thorough check of the proper flags to use

if test "$MPM_NAME" = "mpmt_pthread" ; then

    APACHE_FAST_OUTPUT(server/mpm/$MPM_NAME/Makefile)

    APACHE_MPM_PTHREAD

fi
