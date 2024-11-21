%global debug_package %{nil}

%define _prefix /opt/xpmem

%define _release_modulefile /opt/cray/modulefiles/xpmem/%{version}-%{release}

Summary: XPMEM: Cross-partition memory
Name: xpmem
Version: 0.2
Release: 0
License: GPLv2
Group: System Environment/Libraries
Packager: HPE
Source: xpmem-%{version}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-build
Requires: xpmem-kmod
Provides: xpmem xpmem-devel

%description
XPMEM is a Linux kernel module that enables a process to map the
memory of another process into its virtual address space.

%prep
%setup -n xpmem-%{version}

%build
./configure --prefix=%{_prefix} --libdir=%{_libdir} --includedir=%{_includedir} --disable-kernel-module --with-module=%{_release_modulefile}  --with-pkgconfig-prefix=/usr/lib64/pkgconfig
make

%install
make DESTDIR=$RPM_BUILD_ROOT install

%__mkdir_p %{buildroot}/etc/ld.so.conf.d
echo %{_libdir} > %{buildroot}/etc/ld.so.conf.d/xpmem.conf

%files
%defattr(-, root, root)
%dir /etc/ld.so.conf.d
/etc/ld.so.conf.d/xpmem.conf
%dir %{_prefix}
%{_prefix}
%{_release_modulefile}
/usr/lib64/pkgconfig/xpmem.pc

%post
/sbin/ldconfig

%postun
/sbin/ldconfig
