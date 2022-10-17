#/bin/sh

set -ex

yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
yum -y install rh-python36 lcov

scl enable rh-python36 "pip3 install meson==0.60.3"
scl enable rh-python36 "pip3 install lcov-cobertura"
scl enable rh-python36 "pip3 install ninja"

yum clean all
