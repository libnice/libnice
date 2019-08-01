# build with
# docker build -t registry.freedesktop.org/libnice/libnice/centos7/autotools-build:$(date --rfc-3339=date) .
# docker tag  registry.freedesktop.org/libnice/libnice/centos7/autotools-build:$(date --rfc-3339=date)  registry.freedesktop.org/libnice/libnice/centos7/autotools-build:latest
# docker push registry.freedesktop.org/libnice/libnice/centos7/autotools-build:$(date --rfc-3339=date)
# docker push registry.freedesktop.org/libnice/libnice/centos7/autotools-build:latest

# alternatively

# export BUILDAH_FORMAT=docker
# buildah bud -t registry.freedesktop.org/libnice/libnice/centos7/autotools-build:$(date --rfc-3339=date) .
# buildah tag registry.freedesktop.org/libnice/libnice/centos7/autotools-build:$(date --rfc-3339=date) registry.freedesktop.org/libnice/libnice/centos7/autotools-build:latest
# buildah push registry.freedesktop.org/libnice/libnice/centos7/autotools-build:latest
# buildah push registry.freedesktop.org/libnice/libnice/centos7/autotools-build:$(date --rfc-3339=date)

FROM centos:centos7

RUN yum -y update; yum clean all
RUN yum -y install git gtk-doc gnutls-devel gupnp-igd-devel gstreamer1-devel gobject-introspection-devel valgrind; yum clean all

RUN yum -y install autoconf automake libtool; yum clean all
RUN yum -y install net-tools; yum clean all
