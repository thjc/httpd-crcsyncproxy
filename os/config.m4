AC_MSG_CHECKING(for target platform)

#PLATFORM=`${CONFIG_SHELL-/bin/sh} $ac_config_guess`
PLATFORM=$host
LIBPRE=lib

case "$PLATFORM" in
*beos*)
  OS="beos"
  OS_DIR=$OS
  ;;
*pc-os2_emx*)
  LIBPRE=""
  OS="os2"
  OS_DIR=$OS
  ;;
bs2000*)
  OS="unix"
  OS_DIR=bs2000  # only the OS_DIR is platform specific.
  ;;
*)
  OS="unix"
  OS_DIR=$OS;;
esac

AC_MSG_RESULT($OS)
APACHE_FAST_OUTPUT(os/$OS_DIR/Makefile)
