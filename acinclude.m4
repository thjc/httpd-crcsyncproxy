
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

dnl APACHE_MKDIR_P_CHECK
dnl checks whether mkdir -p works
AC_DEFUN(APACHE_MKDIR_P_CHECK,[
  AC_CACHE_CHECK(for working mkdir -p, ac_cv_mkdir_p,[
    test -d conftestdir && rm -rf conftestdir
    mkdir -p conftestdir/somedir >/dev/null 2>&1
    if test -d conftestdir/somedir; then
      ac_cv_mkdir_p=yes
    else
      ac_cv_mkdir_p=no
    fi
    rm -rf conftestdir
  ])
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
  APACHE_SUBST(libexecdir)
  APACHE_SUBST(htdocsdir)
  APACHE_SUBST(manualdir)
  APACHE_SUBST(includedir)
  APACHE_SUBST(errordir)
  APACHE_SUBST(iconsdir)
  APACHE_SUBST(sysconfdir)
  APACHE_SUBST(installbuilddir)
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
  APACHE_SUBST(CORE_IMPLIB_FILE)
  APACHE_SUBST(CORE_IMPLIB)
  APACHE_SUBST(SH_LIBTOOL)
  APACHE_SUBST(MK_IMPLIB)
  APACHE_SUBST(INSTALL_PROG_FLAGS)

  abs_srcdir="`(cd $srcdir && pwd)`"

  APACHE_MKDIR_P_CHECK
  echo creating config_vars.mk
  > config_vars.mk
  for i in $APACHE_VAR_SUBST; do
    eval echo "$i = \$$i" >> config_vars.mk
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
dnl   yes  -- enabled by default. user must explicitly disable.
dnl   no   -- disabled under default, most, all. user must explicitly enable.
dnl   most -- disabled by default. enabled explicitly or with most or all.
dnl   ""   -- disabled under default, most. enabled explicitly or with all.
dnl
dnl basically: yes/no is a hard setting. "most" means follow the "most"
dnl            setting. otherwise, fall under the "all" setting.
dnl            explicit yes/no always overrides.
dnl
AC_DEFUN(APACHE_MODULE,[
  AC_MSG_CHECKING(whether to enable mod_$1)
  define([optname],[  --]ifelse($5,yes,disable,enable)[-]translit($1,_,-))dnl
  AC_ARG_ENABLE(translit($1,_,-),optname() substr([                         ],len(optname()))$2,,enable_$1=ifelse($5,,maybe-all,$5))
  undefine([optname])dnl
  _apmod_extra_msg=""
  dnl When --enable-modules=most is set and the module was not explicitly
  dnl requested, allow a module to disable itself if its pre-reqs fail.
  if test "$module_selection" = "most" -a "$enable_$1" = "most"; then
    _apmod_error_fatal="no"
  else
    _apmod_error_fatal="yes"
  fi
  if test "$enable_$1" = "most"; then
    if test "$module_selection" = "most" -o "$module_selection" = "all"; then
      enable_$1=$module_default
      _apmod_extra_msg=" ($module_selection)"
    else
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
      shared=yes;;
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
dnl APACHE_LAYOUT(configlayout, layoutname)
AC_DEFUN(APACHE_LAYOUT,[
  if test ! -f $srcdir/config.layout; then
    echo "** Error: Layout file $srcdir/config.layout not found"
    echo "** Error: Cannot use undefined layout '$LAYOUT'"
    exit 1
  fi
  pldconf=./config.pld
  changequote({,})
  sed -e "1,/[ 	]*<[lL]ayout[ 	]*$2[ 	]*>[ 	]*/d" \
      -e '/[ 	]*<\/Layout>[ 	]*/,$d' \
      -e "s/^[ 	]*//g" \
      -e "s/:[ 	]*/=\'/g" \
      -e "s/[ 	]*$/'/g" \
      $1 > $pldconf
  layout_name=$2
  . $pldconf
  rm $pldconf
  for var in prefix exec_prefix bindir sbindir libexecdir mandir \
             sysconfdir datadir errordir iconsdir htdocsdir cgidir \
             includedir localstatedir runtimedir logfiledir \
             proxycachedir installbuilddir; do
    eval "val=\"\$$var\""
    case $val in
      *+)
        val=`echo $val | sed -e 's;\+$;;'`
        eval "$var=\"\$val\""
        autosuffix=yes
        ;;
      *)
        autosuffix=no
        ;;
    esac
    val=`echo $val | sed -e 's:\(.\)/*$:\1:'`
    val=`echo $val | sed -e 's:$\([a-z_]*\):$(\1):g'`
    if test "$autosuffix" = "yes"; then
      if echo $val | grep apache >/dev/null; then
        addtarget=no
      else
        addtarget=yes
      fi
      if test "$addtarget" = "yes"; then
        val="$val/apache"
      fi
    fi
    eval "$var='$val'"
  done
  changequote([,])
])dnl
dnl
dnl APACHE_ENABLE_LAYOUT
dnl
AC_DEFUN(APACHE_ENABLE_LAYOUT,[
AC_ARG_ENABLE(layout,
[  --enable-layout=LAYOUT],[
  LAYOUT=$enableval
])

if test -z "$LAYOUT"; then
  LAYOUT="Apache"
fi
APACHE_LAYOUT($srcdir/config.layout, $LAYOUT)

AC_MSG_CHECKING(for chosen layout)
AC_MSG_RESULT($layout_name)
])

dnl
dnl APACHE_ENABLE_MODULES
dnl
AC_DEFUN(APACHE_ENABLE_MODULES,[
  module_selection=default
  module_default=yes

  AC_ARG_ENABLE(modules,
  [  --enable-modules=MODULE-LIST],[
    for i in $enableval; do
      if test "$i" = "all" -o "$i" = "most"; then
        module_selection=$i
      else
        eval "enable_$i=yes"
      fi
    done
  ])
  
  AC_ARG_ENABLE(mods-shared,
  [  --enable-mods-shared=MODULE-LIST],[
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
dnl Find the openssl toolkit installation and check it for the right
dnl version, then add its flags to INCLUDES and LIBS.  This should
dnl really be using a custom AC_TRY_COMPILE function to test the includes
dnl and then AC_TRY_LINK to test the libraries directly for the version,
dnl but that will require someone who knows how to program openssl.
dnl
AC_DEFUN(APACHE_CHECK_SSL_TOOLKIT,[
if test "x$ap_ssltk_base" = "x"; then
  AC_MSG_CHECKING(for SSL/TLS toolkit base)
  ap_ssltk_base=""
  AC_ARG_WITH(ssl, [  --with-ssl[=DIR]        SSL/TLS toolkit (OpenSSL)], [
    if test "x$withval" != "xyes" -a "x$withval" != "x"; then
      ap_ssltk_base="$withval"
    fi
  ])
  if test "x$ap_ssltk_base" = "x"; then
    AC_CACHE_VAL(ap_cv_ssltk,[
      #
      # shotgun approach: find all occurrences of the openssl program
      #
      ap_ssltk_try=""
      # The IFS=... trick eliminates the colons from $PATH, without using an external program
      for p in `IFS=":$IFS"; echo $PATH` /usr/local/openssl/bin /usr/local/ssl/bin; do
        if test -f "$p/openssl"; then
          ap_ssltk_try="$ap_ssltk_try $p"
        fi
      done
      if test "x$ap_ssltk_try" = "x"; then
        AC_MSG_ERROR(['openssl' not found in path])
      fi
      for p in $ap_ssltk_try; do
        ap_ssltk_version="`$p/openssl version`"
        case "$ap_ssltk_version" in
            "OpenSSL "[[1-9]]* | \
            "OpenSSL "0.9.[[6-9]]* | \
            "OpenSSL "0.[[1-9]][[0-9]]* )
                ap_cv_ssltk="`(cd $p/.. && pwd)`"
                break
                ;;
            *)
                # skip because it is too old or a bad result
                ;;
        esac
      done
      if test "x$ap_cv_ssltk" = "x"; then
        AC_MSG_ERROR([requires OpenSSL 0.9.6 or higher])
      fi
    ])
    ap_ssltk_base="$ap_cv_ssltk"
  fi
  if test ! -d $ap_ssltk_base; then
    AC_MSG_ERROR([invalid SSL/TLS toolkit base directory $ap_ssltk_base])
  fi
  AC_MSG_RESULT($ap_ssltk_base)
    
  AC_MSG_CHECKING(for SSL/TLS toolkit version)
  AC_MSG_RESULT($ap_ssltk_version)
    
  AC_MSG_CHECKING(for SSL/TLS toolkit includes)
  ap_ssltk_incdir=""
  for p in $ap_ssltk_base/include /usr/local/openssl/include \
           /usr/local/ssl/include /usr/local/include /usr/include; do
    if test -f "$p/openssl/ssl.h"; then
      ap_ssltk_incdir="$p"
      break
    fi
  done
  if test "x$ap_ssltk_incdir" = "x"; then
    AC_MSG_ERROR([OpenSSL headers not found])
  fi
  AC_MSG_RESULT($ap_ssltk_incdir)

  AC_MSG_CHECKING(for SSL/TLS toolkit libraries)
  ap_ssltk_libdir=""
  for p in $ap_ssltk_base/lib /usr/local/openssl/lib \
           /usr/local/ssl/lib /usr/local/lib /usr/lib /lib; do
    if test -f "$p/libssl.a" -o -f "$p/libssl.so"; then
      ap_ssltk_libdir="$p"
      break
    fi
  done
  if test ".$ap_ssltk_libdir" = .; then
    AC_MSG_ERROR([OpenSSL libraries not found])
  fi
  AC_MSG_RESULT($ap_ssltk_libdir)

  dnl #  annotate the Apache build environment with determined information
  APR_ADDTO(INCLUDES, [-I$ap_ssltk_incdir/openssl])
  if test "x$ap_ssltk_incdir" != "x/usr/include"; then
    APR_ADDTO(INCLUDES, [-I$ap_ssltk_incdir])
  fi
  if test "x$ap_ssltk_libdir" != "x/usr/lib"; then
    APR_ADDTO(LIBS, [-L$ap_ssltk_libdir])
    if test "x$ap_platform_runtime_link_flag" != "x"; then
      APR_ADDTO(LIBS, [$ap_platform_runtime_link_flag$ap_ssltk_libdir])
    fi
  fi
  APR_ADDTO(LIBS, [-lssl -lcrypto])
  ap_cv_ssltk="$ap_ssltk_base"
fi
])

