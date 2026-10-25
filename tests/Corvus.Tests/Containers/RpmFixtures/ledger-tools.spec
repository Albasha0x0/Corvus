Name:           ledger-tools
Version:        1.2.0
Release:        3
Summary:        Ledger sample package
License:        MIT
BuildArch:      noarch
Requires:       coreutils
Provides:       ledger = 1.2.0

%description
Sums ledger entries; a sample package for the rpm reader tests.

%install
mkdir -p %{buildroot}/usr/bin %{buildroot}/usr/share/ledger/archive %{buildroot}/etc %{buildroot}/var/log
printf '#!/bin/sh\necho "ledger %s"\n' 1.2.0 > %{buildroot}/usr/bin/ledger
chmod 755 %{buildroot}/usr/bin/ledger
ln -s ledger %{buildroot}/usr/bin/ledger-report
printf 'Shipping notes for the ledger sample.\n' > %{buildroot}/usr/share/ledger/notes.txt
printf 'currency=cash\n' > %{buildroot}/etc/ledger.conf

%pre
echo "installing ledger"

%post
echo "installed ledger"

%files
%defattr(-,root,root)
/usr/bin/ledger
/usr/bin/ledger-report
%dir /usr/share/ledger
%dir /usr/share/ledger/archive
/usr/share/ledger/notes.txt
%config(noreplace) /etc/ledger.conf
%ghost /var/log/ledger.log
