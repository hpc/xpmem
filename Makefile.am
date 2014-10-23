SUBDIRS = include \
          kernel \
          lib \
          test

pkgconfig_DATA = cray-xpmem.pc

sysconf_DATA = .version \
	       56-cray-xpmem.rules

.version:
	echo "#%Module" > $@
	echo "set ModulesVersion \"@MODULE_VERSION@\"" >> $@

install-data-local:
	$(INSTALL_DATA) -D $(srcdir)/module $(DESTDIR)@MODULE_PATH@

