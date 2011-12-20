%define mod_name nova2ools

Name:             nova2ools
Version:          0.0.1
Release:          1
Summary:          Tools to work with OpenStack
License:          GNU GPL v3
Vendor:           Grid Dynamics International, Inc.
URL:              http://www.griddynamics.com/openstack
Group:            Development/Languages/Python

Source0:          %{name}-%{version}.tar
BuildRoot:        %{_tmppath}/%{name}-%{version}-build
BuildRequires:    python-setuptools
BuildArch:        noarch
Requires:         python-argparse

%description
Set of command line utilities to work with OpenStack.

%prep
%setup -q -n %{name}

%build
%{__python} setup.py build

%install
%{__python} setup.py install -O1 --skip-build --prefix=%{_prefix} --root=%{buildroot}

%clean
%__rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{python_sitelib}/%{mod_name}
%{_usr}/bin/*

%changelog
* Tue Dec 20 2011 Dmitry Maslennikov <dmaslennikov at griddynamics.com>
- initial release
