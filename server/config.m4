dnl ## Check for libraries

AC_DEFUN(APACHE_DEFINE_HAVE_CRYPT, [
])
AC_CHECK_LIB(nsl, gethostname, [
 AC_ADD_LIBRARY(nsl) ], [])

AC_CHECK_LIB(socket, socket, [
 AC_ADD_LIBRARY(socket) ], [])

AC_CHECK_LIB(nsl, gethostbyaddr, [
 AC_ADD_LIBRARY(nsl) ], [])

AC_CHECK_LIB(crypt, crypt, [
 AC_ADD_LIBRARY(crypt) 
 apache_have_crypt=1
], [
 AC_CHECK_LIB(c, crypt, [
  apache_have_crypt=1
 ], [
  AC_CHECK_LIB(ufc, crypt, [
   AC_ADD_LIBRARY(ufc) 
   apache_have_crypt=1
  ], [])
 ])
])
if test "$apache_have_crypt" = "1" ; then
    AC_DEFINE(HAVE_CRYPT,,[Define if this platform has crypt()])
fi

dnl ## Check for header files

AC_HEADER_STDC
AC_CHECK_HEADERS(
bstring.h \
crypt.h \
unistd.h \
sys/resource.h \
sys/select.h \
sys/processor.h \
)

dnl ## Check for typedefs, structures, and compiler characteristics.

AC_TYPE_RLIM_T
AC_CACHE_CHECK([for tm_gmtoff in struct tm], ac_cv_struct_tm_gmtoff,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <$ac_cv_struct_tm>], [struct tm tm; tm.tm_gmtoff;],
  ac_cv_struct_tm_gmtoff=yes, ac_cv_struct_tm_gmtoff=no)])

if test "$ac_cv_struct_tm_gmtoff" = "yes"; then
    AC_DEFINE(HAVE_GMTOFF,,
        [Define if struct tm has a tm_gmtoff member])
fi

dnl ## Check for library functions

AC_CHECK_FUNCS(
difftime \
syslog \
)
