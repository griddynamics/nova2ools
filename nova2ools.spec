%define mod_name nova2ools

Name:             nova2ools
Version:          0.0.2
Release:          1
Summary:          Tools to work with OpenStack
License:          GNU GPL v3
Vendor:           Grid Dynamics International, Inc.
URL:              http://www.griddynamics.com/openstack
Group:            Development/Languages/Python

Source0:          %{name}-%{version}.tar
BuildRoot:        %{_tmppath}/%{name}-%{version}-build
BuildRequires:    python-setuptools python-argparse python-httplib2
BuildArch:        noarch
Requires:         python-argparse python-httplib2

%description
Set of command line utilities to work with OpenStack.

%prep
%setup -q -n %{name}-%{version}

%build
%{__python} setup.py build

%install
%{__python} setup.py install -O1 --skip-build --prefix=%{_prefix} --root=%{buildroot} --record=INSTALLED_FILES

%clean
%__rm -rf %{buildroot}

%files -f INSTALLED_FILES
%defattr(-,root,root,-)

%changelog
* Tue Dec 20 2011 Dmitry Maslennikov <dmaslennikov at griddynamics.com>
- initial release
