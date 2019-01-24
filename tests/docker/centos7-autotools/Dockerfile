# build with
# docker build -t registry.freedesktop.org/libnice/libnice/centos7/autotools-build:$(date --rfc-3339=date) .
# docker tag  registry.freedesktop.org/libnice/libnice/centos7/autotools-build:$(date --rfc-3339=date)  registry.freedesktop.org/libnice/libnice/centos7/autotools-build:latest
# docker push registry.freedesktop.org/libnice/libnice/centos7/autotools-build:$(date --rfc-3339=date)
# docker push registry.freedesktop.org/libnice/libnice/centos7/autotools-build:latest

FROM centos:centos7

RUN yum -y update; yum clean all
RUN yum -y install git gtk-doc gnutls-devel gupnp-igd-devel gstreamer1-devel gobject-introspection-devel; yum clean all

RUN yum -y install autoconf automake libtool; yum clean all
RUN yum -y install net-tools; yum clean all
