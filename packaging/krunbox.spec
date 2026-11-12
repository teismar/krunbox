Name:           krunbox
Version:        2.0.0
Release:        1%{?dist}
Summary:        Podman & microVM Sandboxing Engine with GTK4 Console

License:        Apache-2.0
URL:            https://github.com/krunbox/krunbox
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  python3-wheel
BuildRequires:  desktop-file-utils
BuildRequires:  libappstream-glib

Requires:       python3
Requires:       python3-rich >= 13.0.0
Requires:       python3-gobject
Requires:       gtk4
Requires:       libadwaita
Requires:       podman >= 4.9.0
Requires:       crun-krun
Requires:       passt
Requires:       openssh-clients

%description
krunbox runs AI coding agents and development environments inside lightweight,
hardware-isolated microVMs on Linux. It combines crun-krun and rootless Podman
with an outbound egress firewall, an in-guest MCP permission gateway, live port
forwarding, workspace git guardrails, and a native GTK4 / Libadwaita desktop console.

%prep
%autosetup -n %{name}-%{version}

%build
%py3_build

%install
%py3_install

# Install desktop entry
desktop-file-install --dir=%{buildroot}%{_datadir}/applications \
    krunbox/data/io.krunbox.Krunbox.desktop

# Install AppStream metadata
install -D -p -m 0644 krunbox/data/io.krunbox.Krunbox.metainfo.xml \
    %{buildroot}%{_metainfodir}/io.krunbox.Krunbox.metainfo.xml

# Install bash completion
install -D -p -m 0644 krunbox/data/krunbox.bash-completion \
    %{buildroot}%{_datadir}/bash-completion/completions/krunbox

# Install icons
for size in 16 24 32 48 64 128 256 512; do
    install -D -p -m 0644 krunbox/data/icons/${size}x${size}/io.krunbox.Krunbox.png \
        %{buildroot}%{_datadir}/icons/hicolor/${size}x${size}/apps/io.krunbox.Krunbox.png
done
install -D -p -m 0644 krunbox/data/icons/io.krunbox.Krunbox.svg \
    %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/io.krunbox.Krunbox.svg
install -D -p -m 0644 krunbox/data/icons/io.krunbox.Krunbox-symbolic.svg \
    %{buildroot}%{_datadir}/icons/hicolor/symbolic/apps/io.krunbox.Krunbox-symbolic.svg

%check
desktop-file-validate %{buildroot}%{_datadir}/applications/io.krunbox.Krunbox.desktop
appstream-util validate-relax --nonet %{buildroot}%{_metainfodir}/io.krunbox.Krunbox.metainfo.xml

%files
%license LICENSE
%doc README.md
%{_bindir}/krunbox
%{_bindir}/krunbox-ui
%{python3_sitelib}/krunbox/
%{python3_sitelib}/krunbox-%{version}*.*-info/
%{_datadir}/applications/io.krunbox.Krunbox.desktop
%{_metainfodir}/io.krunbox.Krunbox.metainfo.xml
%{_datadir}/bash-completion/completions/krunbox
%{_datadir}/icons/hicolor/*/apps/io.krunbox.Krunbox*

%changelog
* Thu Nov 12 2026 Tim Eismar <eismartim@gmail.com> - 2.0.0-1
- Initial 2.0.0 release of krunbox

