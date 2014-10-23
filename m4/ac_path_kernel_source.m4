##
## additional m4 macros
##
## (C) 1999 Christoph Bartelmus (lirc@bartelmus.de)
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
    shortvers="$( uname -r | sed -r 's/(@<:@2-9@:>@\.@<:@0-9@:>@+).*/\1/' )"
    for dir in ${ac_kerneldir} \
        /usr/src/kernel-source-* \
        /usr/src/linux-source-* \
        /usr/src/linux /lib/modules/*/source \
        /lib/modules/*/build
    do
      if test -e $dir/Module.symvers ; then
        kerneldir=`dirname $dir/Makefile`/ || continue
        no_kernel=no
        break
      fi;
    done
  fi

  if test x${no_kernel} = xyes; then
      kerneldir=`pwd`
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
  AC_MSG_CHECKING(for Linux kernel sources)

  AC_ARG_WITH(kerneldir,
    [  --with-kerneldir=DIR    kernel sources in DIR],

    ac_kerneldir=${withval}
    AC_PATH_KERNEL_SOURCE_SEARCH,

    ac_kerneldir=""
    AC_CACHE_VAL(ac_cv_have_kernel,AC_PATH_KERNEL_SOURCE_SEARCH)
  )

  eval "$ac_cv_have_kernel"

  AC_SUBST(kerneldir)
  AC_SUBST(kernelext)
  AC_MSG_RESULT(${kerneldir})
]
)
