#/bin/sh

set -ex

dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
dnf config-manager --set-enabled powertools
dnf install -y lcov ninja-build gtk-doc gupnp-igd-devel

pip3 install meson==0.60.3
pip3 install lcov-cobertura

dnf clean all
