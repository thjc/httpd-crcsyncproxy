
dnl APACHE_HELP_STRING(LHS, RHS)
dnl Autoconf 2.50 can not handle substr correctly.  It does have 
dnl AC_HELP_STRING, so let's try to call it if we can.
dnl Note: this define must be on one line so that it can be properly returned
dnl as the help string.
AC_DEFUN(APACHE_HELP_STRING,[ifelse(regexp(AC_ACVERSION, 2\.1), -1, AC_HELP_STRING($1,$2),[  ]$1 substr([                       ],len($1))$2)])dnl

dnl APACHE_SUBST(VARIABLE)
dnl Makes VARIABLE available in generated files
dnl (do not use @variable@ in Makefiles, but $(variable))
AC_DEFUN(APACHE_SUBST,[
  APACHE_VAR_SUBST="$APACHE_VAR_SUBST $1"
  AC_SUBST($1)
])

dnl APACHE_FAST_OUTPUT(FILENAME)
dnl Perform substitutions on FILENAME (Makefiles only)
AC_DEFUN(APACHE_FAST_OUTPUT,[
  APACHE_FAST_OUTPUT_FILES="$APACHE_FAST_OUTPUT_FILES $1"
])

dnl APACHE_GEN_CONFIG_VARS
dnl Creates config_vars.mk
AC_DEFUN(APACHE_GEN_CONFIG_VARS,[
  APACHE_SUBST(abs_srcdir)
  APACHE_SUBST(bindir)
  APACHE_SUBST(sbindir)
  APACHE_SUBST(cgidir)
  APACHE_SUBST(logfiledir)
  APACHE_SUBST(exec_prefix)
  APACHE_SUBST(datadir)
  APACHE_SUBST(localstatedir)
  APACHE_SUBST(mandir)
  APACHE_SUBST(libdir)
  APACHE_SUBST(libexecdir)
  APACHE_SUBST(htdocsdir)
  APACHE_SUBST(manualdir)
  APACHE_SUBST(includedir)
  APACHE_SUBST(errordir)
  APACHE_SUBST(iconsdir)
  APACHE_SUBST(sysconfdir)
  APACHE_SUBST(installbuilddir)
  APACHE_SUBST(runtimedir)
  APACHE_SUBST(proxycachedir)
  APACHE_SUBST(other_targets)
  APACHE_SUBST(progname)
  APACHE_SUBST(prefix)
  APACHE_SUBST(AWK)
  APACHE_SUBST(CC)
  APACHE_SUBST(CPP)
  APACHE_SUBST(CXX)
  APACHE_SUBST(CPPFLAGS)
  APACHE_SUBST(CFLAGS)
  APACHE_SUBST(CXXFLAGS)
  APACHE_SUBST(LTFLAGS)
  APACHE_SUBST(LDFLAGS)
  APACHE_SUBST(LT_LDFLAGS)
  APACHE_SUBST(SH_LDFLAGS)
  APACHE_SUBST(HTTPD_LDFLAGS)
  APACHE_SUBST(UTIL_LDFLAGS)
  APACHE_SUBST(LIBS)
  APACHE_SUBST(DEFS)
  APACHE_SUBST(INCLUDES)
  APACHE_SUBST(NOTEST_CPPFLAGS)
  APACHE_SUBST(NOTEST_CFLAGS)
  APACHE_SUBST(NOTEST_CXXFLAGS)
  APACHE_SUBST(NOTEST_LDFLAGS)
  APACHE_SUBST(NOTEST_LIBS)
  APACHE_SUBST(EXTRA_CPPFLAGS)
  APACHE_SUBST(EXTRA_CFLAGS)
  APACHE_SUBST(EXTRA_CXXFLAGS)
  APACHE_SUBST(EXTRA_LDFLAGS)
  APACHE_SUBST(EXTRA_LIBS)
  APACHE_SUBST(EXTRA_INCLUDES)
  APACHE_SUBST(LIBTOOL)
  APACHE_SUBST(SHELL)
  APACHE_SUBST(MODULE_DIRS)
  APACHE_SUBST(MODULE_CLEANDIRS)
  APACHE_SUBST(PORT)
  APACHE_SUBST(nonssl_listen_stmt_1)
  APACHE_SUBST(nonssl_listen_stmt_2)
  APACHE_SUBST(CORE_IMPLIB_FILE)
  APACHE_SUBST(CORE_IMPLIB)
  APACHE_SUBST(SH_LIBS)
  APACHE_SUBST(SH_LIBTOOL)
  APACHE_SUBST(MK_IMPLIB)
  APACHE_SUBST(MKDEP)
  APACHE_SUBST(INSTALL_PROG_FLAGS)
  APACHE_SUBST(DSO_MODULES)
  APACHE_SUBST(APR_BINDIR)
  APACHE_SUBST(APR_INCLUDEDIR)
  APACHE_SUBST(APU_BINDIR)
  APACHE_SUBST(APU_INCLUDEDIR)

  abs_srcdir="`(cd $srcdir && pwd)`"

  echo creating config_vars.mk
  test -d build || $mkdir_p build
  > build/config_vars.mk
  for i in $APACHE_VAR_SUBST; do
    eval echo "$i = \$$i" >> build/config_vars.mk
  done
])

dnl APACHE_GEN_MAKEFILES
dnl Creates Makefiles
AC_DEFUN(APACHE_GEN_MAKEFILES,[
  $SHELL $srcdir/build/fastgen.sh $srcdir $ac_cv_mkdir_p $BSD_MAKEFILE $APACHE_FAST_OUTPUT_FILES
])

dnl ## APACHE_OUTPUT(file)
dnl ## adds "file" to the list of files generated by AC_OUTPUT
dnl ## This macro can be used several times.
AC_DEFUN(APACHE_OUTPUT, [
  APACHE_OUTPUT_FILES="$APACHE_OUTPUT_FILES $1"
])

dnl
dnl APACHE_TYPE_RLIM_T
dnl
dnl If rlim_t is not defined, define it to int
dnl
AC_DEFUN(APACHE_TYPE_RLIM_T, [
  AC_CACHE_CHECK([for rlim_t], ac_cv_type_rlim_t, [
    AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
], [rlim_t spoon;], [
      ac_cv_type_rlim_t=yes
    ],[ac_cv_type_rlim_t=no
    ])
  ])
  if test "$ac_cv_type_rlim_t" = "no" ; then
      AC_DEFINE(rlim_t, int,
          [Define to 'int' if <sys/resource.h> doesn't define it for us])
  fi
])

dnl APACHE_MODPATH_INIT(modpath)
AC_DEFUN(APACHE_MODPATH_INIT,[
  current_dir=$1
  modpath_current=modules/$1
  modpath_static=
  modpath_shared=
  test -d $1 || $srcdir/build/mkdir.sh $modpath_current
  > $modpath_current/modules.mk
])dnl
dnl
AC_DEFUN(APACHE_MODPATH_FINISH,[
  echo "DISTCLEAN_TARGETS = modules.mk" >> $modpath_current/modules.mk
  echo "static = $modpath_static" >> $modpath_current/modules.mk
  echo "shared = $modpath_shared" >> $modpath_current/modules.mk
  if test ! -z "$modpath_static" -o ! -z "$modpath_shared"; then
    MODULE_DIRS="$MODULE_DIRS $current_dir"
  else
    MODULE_CLEANDIRS="$MODULE_CLEANDIRS $current_dir"
  fi
  APACHE_FAST_OUTPUT($modpath_current/Makefile)
])dnl
dnl
dnl APACHE_MODPATH_ADD(name[, shared[, objects [, ldflags[, libs]]]])
AC_DEFUN(APACHE_MODPATH_ADD,[
  if test -z "$3"; then
    objects="mod_$1.lo"
  else
    objects="$3"
  fi

  if test -z "$module_standalone"; then
    if test -z "$2"; then
      libname="mod_$1.la"
      BUILTIN_LIBS="$BUILTIN_LIBS $modpath_current/$libname"
      modpath_static="$modpath_static $libname"
      cat >>$modpath_current/modules.mk<<EOF
$libname: $objects
	\$(MOD_LINK) $objects
EOF
    else
      apache_need_shared=yes
      libname="mod_$1.la"
      shobjects=`echo $objects | sed 's/\.lo/.slo/g'`
      modpath_shared="$modpath_shared $libname"
      cat >>$modpath_current/modules.mk<<EOF
$libname: $shobjects
	\$(SH_LINK) -rpath \$(libexecdir) -module -avoid-version $4 $objects $5
EOF
    fi
  fi
])dnl

dnl
dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])
dnl
dnl default is one of:
dnl   yes    -- enabled by default. user must explicitly disable.
dnl   no     -- disabled under default, most, all. user must explicitly enable.
dnl   most   -- disabled by default. enabled explicitly or with most or all.
dnl   static -- enabled as static by default, must be explicitly changed.
dnl   ""     -- disabled under default, most. enabled explicitly or with all.
dnl
dnl basically: yes/no is a hard setting. "most" means follow the "most"
dnl            setting. otherwise, fall under the "all" setting.
dnl            explicit yes/no always overrides.
dnl
AC_DEFUN(APACHE_MODULE,[
  AC_MSG_CHECKING(whether to enable mod_$1)
  define([optname],[--]ifelse($5,yes,disable,enable)[-]translit($1,_,-))dnl
  AC_ARG_ENABLE(translit($1,_,-),APACHE_HELP_STRING(optname(),$2),,enable_$1=ifelse($5,,maybe-all,$5))
  undefine([optname])dnl
  _apmod_extra_msg=""
  dnl When --enable-modules=most is set and the module was not explicitly
  dnl requested, allow a module to disable itself if its pre-reqs fail.
  if test "$module_selection" = "most" -a "$enable_$1" = "most"; then
    _apmod_error_fatal="no"
  else
    _apmod_error_fatal="yes"
  fi
  if test "$enable_$1" = "static"; then
    enable_$1=yes
  elif test "$enable_$1" = "yes"; then
    enable_$1=$module_default
    _apmod_extra_msg=" ($module_selection)"
  elif test "$enable_$1" = "most"; then
    if test "$module_selection" = "most" -o "$module_selection" = "all"; then
      enable_$1=$module_default
      _apmod_extra_msg=" ($module_selection)"
    elif test "$enable_$1" != "yes"; then
      enable_$1=no
    fi
  elif test "$enable_$1" = "maybe-all"; then
    if test "$module_selection" = "all"; then
      enable_$1=$module_default
      _apmod_extra_msg=" (all)"
    else
      enable_$1=no
    fi
  fi
  if test "$enable_$1" != "no"; then
    dnl If we plan to enable it, allow the module to run some autoconf magic
    dnl that may disable it because of missing dependencies.
    ifelse([$6],,:,[AC_MSG_RESULT([checking dependencies])
                    $6
                    AC_MSG_CHECKING(whether to enable mod_$1)
                    if test "$enable_$1" = "no"; then
                      if test "$_apmod_error_fatal" = "no"; then
                        _apmod_extra_msg=" (disabled)"
                      else
                        AC_MSG_ERROR([mod_$1 has been requested but can not be built due to prerequisite failures])
                      fi
                    fi])
  fi
  AC_MSG_RESULT($enable_$1$_apmod_extra_msg)
  if test "$enable_$1" != "no"; then
    case "$enable_$1" in
    shared*)
      enable_$1=`echo $ac_n $enable_$1$ac_c|sed 's/shared,*//'`
      sharedobjs=yes
      shared=yes
      DSO_MODULES="$DSO_MODULES $1"
      ;;
    *)
      MODLIST="$MODLIST ifelse($4,,$1,$4)"
      if test "$1" = "so"; then
          sharedobjs=yes
      fi
      shared="";;
    esac
    APACHE_MODPATH_ADD($1, $shared, $3)
  fi
])dnl

dnl
dnl APACHE_ENABLE_MODULES
dnl
AC_DEFUN(APACHE_ENABLE_MODULES,[
  module_selection=default
  module_default=yes

  AC_ARG_ENABLE(modules,
  APACHE_HELP_STRING(--enable-modules=MODULE-LIST,Modules to enable),[
    for i in $enableval; do
      if test "$i" = "all" -o "$i" = "most"; then
        module_selection=$i
      else
        eval "enable_$i=yes"
      fi
    done
  ])
  
  AC_ARG_ENABLE(mods-shared,
  APACHE_HELP_STRING(--enable-mods-shared=MODULE-LIST,Shared modules to enable),[
    for i in $enableval; do
      if test "$i" = "all" -o "$i" = "most"; then
        module_selection=$i
        module_default=shared
      else
        i=`echo $i | sed 's/-/_/g'`
    	eval "enable_$i=shared"
      fi
    done
  ])
])

AC_DEFUN(APACHE_REQUIRE_CXX,[
  if test -z "$apache_cxx_done"; then
    AC_PROG_CXX
    AC_PROG_CXXCPP
    apache_cxx_done=yes
  fi
])

dnl
dnl APACHE_CHECK_SSL_TOOLKIT
dnl
dnl Configure for the detected openssl/ssl-c toolkit installation, giving
dnl preference to "--with-ssl=<path>" if it was specified.
dnl
AC_DEFUN(APACHE_CHECK_SSL_TOOLKIT,[
if test "x$ap_ssltk_configured" = "x"; then
  dnl initialise the variables we use
  ap_ssltk_base=""
  ap_ssltk_inc=""
  ap_ssltk_lib=""
  ap_ssltk_type=""

  dnl Determine the SSL/TLS toolkit's base directory, if any
  AC_MSG_CHECKING(for SSL/TLS toolkit base)
  AC_ARG_WITH(sslc, APACHE_HELP_STRING(--with-sslc=DIR,RSA SSL-C SSL/TLS toolkit), [
    dnl If --with-sslc specifies a directory, we use that directory or fail
    if test "x$withval" != "xyes" -a "x$withval" != "x"; then
      dnl This ensures $withval is actually a directory and that it is absolute
      ap_ssltk_base="`cd $withval ; pwd`"
    fi
    ap_ssltk_type="sslc"
  ])
  AC_ARG_WITH(ssl, APACHE_HELP_STRING(--with-ssl=DIR,OpenSSL SSL/TLS toolkit), [
    dnl If --with-ssl specifies a directory, we use that directory or fail
    if test "x$withval" != "xyes" -a "x$withval" != "x"; then
      dnl This ensures $withval is actually a directory and that it is absolute
      ap_ssltk_base="`cd $withval ; pwd`"
    fi
  ])
  if test "x$ap_ssltk_base" = "x"; then
    AC_MSG_RESULT(none)
  else
    AC_MSG_RESULT($ap_ssltk_base)
  fi

  dnl Run header and version checks
  saved_CPPFLAGS=$CPPFLAGS
  if test "x$ap_ssltk_base" != "x"; then
    ap_ssltk_inc="-I$ap_ssltk_base/include"
    CPPFLAGS="$CPPFLAGS $ap_ssltk_inc"
  fi
  if test "x$ap_ssltk_type" = "x"; then
    AC_MSG_CHECKING(for OpenSSL version)
    dnl First check for manditory headers
    AC_CHECK_HEADERS([openssl/opensslv.h openssl/ssl.h], [ap_ssltk_type="openssl"], [])
    if test "$ap_ssltk_type" = "openssl"; then
      dnl so it's OpenSSL - test for a good version
      AC_TRY_COMPILE([#include <openssl/opensslv.h>],[
#if !defined(OPENSSL_VERSION_NUMBER)
#error "Missing openssl version"
#endif
#if  (OPENSSL_VERSION_NUMBER < 0x009060af) \
 || ((OPENSSL_VERSION_NUMBER > 0x00907000) && (OPENSSL_VERSION_NUMBER < 0x0090702f))
#error "Insecure openssl version " OPENSSL_VERSION_TEXT
#endif],
      [AC_MSG_RESULT(OK)],
      [dnl Replace this with OPENSSL_VERSION_TEXT from opensslv.h?
       AC_MSG_RESULT([not encouraging])
       echo "WARNING: OpenSSL version may contain security vulnerabilities!"
       echo "         Ensure the latest security patches have been applied!"
      ])
      dnl Look for additional, possibly missing headers
      AC_CHECK_HEADERS(openssl/engine.h)
    else
      AC_MSG_RESULT([no OpenSSL headers found])
    fi
  fi
  if test "$ap_ssltk_type" != "openssl"; then
    dnl Might be SSL-C - report, then test anything relevant
    AC_MSG_CHECKING(for SSL-C version)
    AC_CHECK_HEADERS([sslc.h], [ap_ssltk_type="sslc"], [ap_ssltk_type=""])
    if test "$ap_ssltk_type" = "sslc"; then
      AC_MSG_CHECKING(for SSL-C version)
      AC_TRY_COMPILE([#include <sslc.h>],[
#if !defined(SSLC_VERSION_NUMBER)
#error "Missing SSL-C version"
#endif
#if SSLC_VERSION_NUMBER < 0x2310
#define stringize_ver(x) #x
#error "Insecure SSL-C version " stringize_ver(SSLC_VERSION_NUMBER)
#endif],
      [AC_MSG_RESULT(OK)],
      [dnl Replace this with SSLC_VERSION_NUMBER?
       AC_MSG_RESULT([not encouraging])
       echo "WARNING: SSL-C version may contain security vulnerabilities!"
       echo "         Ensure the latest security patches have been applied!"
      ])
    else
      AC_MSG_RESULT([no SSL-C headers found])
    fi
  fi
  dnl restore
  CPPFLAGS=$saved_CPPFLAGS
  if test "x$ap_ssltk_type" = "x"; then
    AC_MSG_ERROR([...No recognized SSL/TLS toolkit detected])
  fi

  dnl Run library and function checks
  saved_LDFLAGS=$LDFLAGS
  saved_LIBS=$LIBS
  if test "x$ap_ssltk_base" != "x"; then
    if test -d "$ap_ssltk_base/lib"; then
      ap_ssltk_lib="$ap_ssltk_base/lib"
    else
      ap_ssltk_lib="$ap_ssltk_base"
    fi
    LDFLAGS="$LDFLAGS -L$ap_ssltk_lib"
  fi
  dnl make sure "other" flags are available so libcrypto and libssl can link
  LIBS="$LIBS `$apr_config --libs`"
  liberrors=""
  if test "$ap_ssltk_type" = "openssl"; then
    AC_CHECK_LIB(crypto, SSLeay_version, [], [liberrors="yes"])
    AC_CHECK_LIB(ssl, SSL_CTX_new, [], [liberrors="yes"])
    AC_CHECK_FUNCS(ENGINE_init)
    AC_CHECK_FUNCS(ENGINE_load_builtin_engines)
  else
    AC_CHECK_LIB(sslc, SSLC_library_version, [], [liberrors="yes"])
    AC_CHECK_LIB(sslc, SSL_CTX_new, [], [liberrors="yes"])
    AC_CHECK_FUNCS(SSL_set_state)
  fi
  AC_CHECK_FUNCS(SSL_set_cert_store)
  dnl restore
  LDFLAGS=$saved_LDFLAGS
  LIBS=$saved_LIBS
  if test "x$liberrors" != "x"; then
    AC_MSG_ERROR([... Error, SSL/TLS libraries were missing or unusable])
  fi

  dnl Adjust apache's configuration based on what we found above.
  dnl (a) define preprocessor symbols
  if test "$ap_ssltk_type" = "openssl"; then
    AC_DEFINE(HAVE_OPENSSL, 1, [Define if SSL is supported using OpenSSL])
  else
    AC_DEFINE(HAVE_SSLC, 1, [Define if SSL is supported using SSL-C])
  fi
  dnl (b) hook up include paths
  if test "x$ap_ssltk_inc" != "x"; then
    APR_ADDTO(INCLUDES, [$ap_ssltk_inc])
  fi
  dnl (c) hook up linker paths
  if test "x$ap_ssltk_lib" != "x"; then
    APR_ADDTO(LDFLAGS, ["-L$ap_ssltk_lib"])
    if test "x$ap_platform_runtime_link_flag" != "x"; then
      APR_ADDTO(LDFLAGS, ["$ap_platform_runtime_link_flag$ap_ssltk_lib"])
    fi
  fi
  dnl (d) add "-lssl -lcrypto" OR "-lsslc" to LIBS because restoring LIBS
  dnl after AC_CHECK_LIB() obliterates any flags AC_CHECK_LIB() added.
  if test "$ap_ssltk_type" = "openssl"; then
    APR_ADDTO(LIBS, [-lssl -lcrypto])
  else
    APR_ADDTO(LIBS, [-lsslc])
  fi
fi
])

dnl
dnl APACHE_EXPORT_ARGUMENTS
dnl Export (via APACHE_SUBST) the various path-related variables that
dnl apache will use while generating scripts like autoconf and apxs and
dnl the default config file.

AC_DEFUN(APACHE_SUBST_EXPANDED_ARG,[
  APR_EXPAND_VAR(exp_$1, [$]$1)
  APACHE_SUBST(exp_$1)
  APR_PATH_RELATIVE(rel_$1, [$]exp_$1, ${prefix})
  APACHE_SUBST(rel_$1)
])

AC_DEFUN(APACHE_EXPORT_ARGUMENTS,[
  APACHE_SUBST_EXPANDED_ARG(exec_prefix)
  APACHE_SUBST_EXPANDED_ARG(bindir)
  APACHE_SUBST_EXPANDED_ARG(sbindir)
  APACHE_SUBST_EXPANDED_ARG(libdir)
  APACHE_SUBST_EXPANDED_ARG(libexecdir)
  APACHE_SUBST_EXPANDED_ARG(mandir)
  APACHE_SUBST_EXPANDED_ARG(sysconfdir)
  APACHE_SUBST_EXPANDED_ARG(datadir)
  APACHE_SUBST_EXPANDED_ARG(installbuilddir)
  APACHE_SUBST_EXPANDED_ARG(errordir)
  APACHE_SUBST_EXPANDED_ARG(iconsdir)
  APACHE_SUBST_EXPANDED_ARG(htdocsdir)
  APACHE_SUBST_EXPANDED_ARG(manualdir)
  APACHE_SUBST_EXPANDED_ARG(cgidir)
  APACHE_SUBST_EXPANDED_ARG(includedir)
  APACHE_SUBST_EXPANDED_ARG(localstatedir)
  APACHE_SUBST_EXPANDED_ARG(runtimedir)
  APACHE_SUBST_EXPANDED_ARG(logfiledir)
  APACHE_SUBST_EXPANDED_ARG(proxycachedir)
])

