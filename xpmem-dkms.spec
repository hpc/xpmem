%global debug_package %{nil}

%define intranamespace_name xpmem-dkms
%define version 2.6.5
%define source_name %{intranamespace_name}-%{version}

Summary: XPMEM: Cross-partition memory
Name: %{intranamespace_name}-dkms
Version: %{version}
Release: 0
License: GPLv2
Group: System Environment/Kernel
Packager: HPE
Source: xpmem-2.6.5.tar.bz2
Requires: dkms
Provides: kmod(xpmem.ko)
BuildArch: noarch

%description
XPMEM is a Linux kernel module that enables a process to map the
memory of another process into its virtual address space. Source code
can be obtained by cloning the Git repository, original Mercurial
repository or by downloading a tarball from the link above.

%prep
%setup -n %{source_name}
dest_src=/usr/src/%{intranamespace_name}-%{version}-%{release}
mkdir -p %{buildroot}/$dest_src
mkdir -p %{buildroot}%{_udevrulesdir}

cp -r include %{buildroot}$dest_src
cp -r kernel %{buildroot}$dest_src
cp usr/56-xpmem.rules %{buildroot}%{_udevrulesdir}/56-xpmem.rules
echo "%dir $dest_src" > dkms-files
echo "$dest_src" >> dkms-files

dkms_conf=%{buildroot}$dest_src/dkms.conf

cat > $dkms_conf << EOF
PACKAGE_NAME='%{intranamespace_name}'
PACKAGE_VERSION='%{version}-%{release}'
kernelver=\${kernelver:-\$(uname -r)}
kernel_source_dir=\${kernel_source_dir:-/lib/modules/\$kernelver/build}
# Module name, source and destination directories, and build command-line
STRIP[0]='no'
BUILT_MODULE_NAME[0]='%{intranamespace_name}'
BUILT_MODULE_LOCATION[0]='./kernel'
DEST_MODULE_LOCATION[0]='/kernel/../updates/dkms'
MAKE='make -C \$kernel_source_dir modules M=\$dkms_tree/%{intranamespace_name}/%{version}-%{release}/build/kernel'
# Cleanup command-line
CLEAN='make -C \$kernel_source_dir clean M=\$dkms_tree/%{intranamespace_name}/%{version}-%{release}/build'
# Rebuild and autoinstall automatically when dkms_autoinstaller runs for a new kernel
AUTOINSTALL='yes'
EOF

%__mkdir_p %{buildroot}%{_modulesloaddir}
%__install --mode=0644 usr/xpmem.conf %{buildroot}%{_modulesloaddir}/xpmem.conf
%__mkdir_p %{buildroot}%{_udevrulesdir}
%__install --mode=0644 usr/56-xpmem.rules %{buildroot}%{_udevrulesdir}/56-xpmem.rules

%preun
/usr/sbin/dkms remove -m %{intranamespace_name} -v %{version}-%{release} --all --rpm_safe_upgrade
exit 0

%post
postinst=/usr/libexec/dkms/common.postinst
if [ ! -x $postinst ]; then
    postinst=/usr/lib/dkms/common.postinst
fi
if [ -x $postinst ]; then
    $postinst %{intranamespace_name} %{version}-%{release}
else
    echo "WARNING: $postinst does not exist."
fi

%files -f dkms-files
%dir %{_modulesloaddir}
%{_modulesloaddir}/xpmem.conf
%dir %{_udevrulesdir}
%{_udevrulesdir}/56-xpmem.rules
