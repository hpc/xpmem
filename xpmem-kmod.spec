#define buildforkernels newest
#define buildforkernels current
#define buildforkernels akmod

%define kernel_release %(uname -r | sed -e 's/\.[^.]*$//g')
%global debug_package %{nil}

Summary: XPMEM: Cross-partition memory
Name: xpmem-kmod-%{kernel_release}
Version: 2.6.5
Release: 0
License: GPLv2
Group: System Environment/Kernel
Packager: HPE
Source: xpmem-0.2.tar.bz2
BuildRoot: %{_tmppath}/%{name}-0.2-build
Requires: kernel = %{kernel_release}
Provides: xpmem-kmod

%description
XPMEM is a Linux kernel module that enables a process to map the
memory of another process into its virtual address space. Source code
can be obtained by cloning the Git repository, original Mercurial
repository or by downloading a tarball from the link above.

%prep
%setup -n xpmem-kmod-%{kernel_release}-%{version}

%build
./configure --prefix=/opt/xpmem
pushd kernel ; make ; popd

%install
pushd kernel ; make DESTDIR=$RPM_BUILD_ROOT install ; popd
mkdir -p $RPM_BUILD_ROOT%{_udevrulesdir}
mkdir -p $RPM_BUILD_ROOT/lib/modules/$(uname -r)/kernel/extra
cp usr/56-xpmem.rules $RPM_BUILD_ROOT%{_udevrulesdir}
cp $RPM_BUILD_ROOT/opt/xpmem/lib/modules/$(uname -r)/kernel/xpmem/xpmem.ko $RPM_BUILD_ROOT/lib/modules/$(uname -r)/kernel/extra

%post
touch %{_udevrulesdir}/56-xpmem.rules
depmod -a

%files
%defattr(-, root, root)
/opt
/lib/modules

%config(noreplace)
%{_udevrulesdir}/56-xpmem.rules
