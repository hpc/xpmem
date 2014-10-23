#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([cray-xpmem], [0.1], [http://bugzilla.us.cray.com])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_CONFIG_SRCDIR([include/xpmem.h])
AM_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AM_PROG_LIBTOOL
AC_PROG_LN_S
AM_PROG_AR

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h stdlib.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_C_VOLATILE

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MMAP
AC_CHECK_FUNCS([getpagesize memset])

AC_SUBST([initdir], [${sysconfdir}/init.d])
AC_SUBST([ldsoconfdir], [/etc/ld.so.conf.d])
AC_SUBST([pkgconfigdir], [${libdir}/pkgconfig])

AC_ARG_WITH([default-prefix],
  [AS_HELP_STRING([--with-default-prefix=PATH],
     [PATH to use in place of ${prefix} for default paths.])],
  [AC_SUBST([default_prefix], $withval)],
  [AC_SUBST([default_prefix], "")])

AC_ARG_WITH([default-libdir],
  [AS_HELP_STRING([--with-default-libdir=PATH],
     [Default PATH for libraries.])],
  [AC_SUBST([default_libdir], $withval)],
  [if test -z "${default_prefix}"
   then
       AC_MSG_ERROR([Default library path or default prefix must be specified])
   else
       default_libdir=${libdir//${prefix}/${default_prefix}}
       AC_SUBST([default_libdir])
   fi])

AC_ARG_WITH([module],
  [AS_HELP_STRING([--with-module=PATH],
     [use $PATH as name of module file to write.])],
  [AC_SUBST([MODULE_PATH], $withval)
   AC_SUBST([MODULE_VERSION], [`basename $withval`])],
  [AC_MSG_ERROR([Module path must be specified])])

AC_CONFIG_FILES([Makefile
                 cray-xpmem.pc
                 module
                 include/Makefile
                 kernel/Kbuild
                 kernel/Makefile
                 kernel/xpmem
                 lib/Makefile
                 lib/cray-xpmem.conf
                 test/Makefile
                 test/run.sh])
AC_OUTPUT
