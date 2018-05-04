##
## additional m4 macros
##
## (C) 1999 Christoph Bartelmus (lirc@bartelmus.de)
## (C) 2016-2018 Nathan Hjelm
##


dnl check for kernel source

AC_DEFUN([AC_PATH_KERNEL_SOURCE_SEARCH],
[
  kerneldir=missing
  kernelext=ko
  no_kernel=yes

  if test `uname` != "Linux"; then
    kerneldir="not running Linux"
  else
    vers="$(uname -r)"
    for dir in ${ac_kerneldir} \
        /lib/modules/${vers}/build \
        /usr/src/kernel-source-* \
        /usr/src/linux-source-${vers} \
        /usr/src/linux /lib/modules/${vers}/source
    do
      if test -e $dir/Module.symvers ; then
        kerneldir=`dirname $dir/Makefile`/ || continue
        no_kernel=no
        break
      fi;
    done
  fi

  if test x${no_kernel} = xyes; then
      AC_MSG_ERROR([could not find kernel sources])
  fi
  ac_cv_have_kernel="no_kernel=${no_kernel} \
                kerneldir=\"${kerneldir}\" \
                kernelext=\"ko\""
]
)

AC_DEFUN([AC_PATH_KERNEL_SOURCE],
[
  AC_CHECK_PROG(ac_pkss_mktemp,mktemp,yes,no)
  AC_PROVIDE([AC_PATH_KERNEL_SOURCE])

  AC_ARG_ENABLE([kernel-module],[Enable building the kernel module (default: enabled)],[build_kernel_module=$enableval],
		[build_kernel_module=1])
  AS_IF([test $build_kernel_module = 1],[

  AC_MSG_CHECKING([for Linux kernel sources])
  kernelvers=$(uname -r)

  AC_ARG_WITH(kerneldir,
    [  --with-kerneldir=DIR    kernel sources in DIR],

    ac_kerneldir=${withval}

    if test -n "$ac_kerneldir" ; then
	if test ! ${ac_kerneldir#/lib/modules} = ${ac_kerneldir} ; then
	    kernelvers=$(basename $(dirname ${ac_kerneldir}))
	elif test ! ${ac_kerneldir#*linux-headers-} = ${ac_kerneldir} ; then
	    # special case to deal with the way the travis script does headers
	    kernelvers=${ac_kerneldir#*linux-headers-}
	else
	    kernelvers=$(make -s kernelrelease -C ${ac_kerneldir} M=dummy 2>/dev/null)
	fi
    fi

    AC_PATH_KERNEL_SOURCE_SEARCH,

    ac_kerneldir=""
    AC_CACHE_VAL(ac_cv_have_kernel,AC_PATH_KERNEL_SOURCE_SEARCH)
  )

  AC_ARG_WITH(kernelvers, [--with-kernelvers=VERSION   kernel release name], kernelvers=${with_kernelvers})

  eval "$ac_cv_have_kernel"

  AC_SUBST(kerneldir)
  AC_SUBST(kernelext)
  AC_SUBST(kernelvers)
  AC_MSG_RESULT(${kerneldir})

  AC_MSG_CHECKING([kernel release])
  AC_MSG_RESULT([${kernelvers}])
  ])
  AM_CONDITIONAL([BUILD_KERNEL_MODULE], [test $build_kernel_module = 1])
]
)
