# build with
# docker build -t registry.freedesktop.org/libnice/libnice/centos7/meson-build:$(date --rfc-3339=date) .
# docker tag registry.freedesktop.org/libnice/libnice/centos7/meson-build:$(date --rfc-3339=date) registry.freedesktop.org/libnice/libnice/centos7/meson-build:latest
# docker push registry.freedesktop.org/libnice/libnice/centos7/meson-build:latest
# docker push registry.freedesktop.org/libnice/libnice/centos7/meson-build:$(date --rfc-3339=date)

# alternatively

# export BUILDAH_FORMAT=docker
# buildah bud -t registry.freedesktop.org/libnice/libnice/centos7/meson-build:$(date --rfc-3339=date) .
# buildah tag registry.freedesktop.org/libnice/libnice/centos7/meson-build:$(date --rfc-3339=date) registry.freedesktop.org/libnice/libnice/centos7/meson-build:latest
# buildah push registry.freedesktop.org/libnice/libnice/centos7/meson-build:latest
# buildah push registry.freedesktop.org/libnice/libnice/centos7/meson-build:$(date --rfc-3339=date)

FROM centos:centos7

RUN yum -y update; yum clean all
RUN yum -y install git gtk-doc gnutls-devel gupnp-igd-devel gstreamer1-devel gobject-introspection-devel valgrind; yum clean all
RUN yum -y install net-tools; yum clean all


RUN yum -y install centos-release-scl ; yum clean all
RUN yum -y install rh-python36; yum clean all
RUN scl enable rh-python36 "pip3 install meson"

RUN yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm; yum clean all
RUN yum -y install ninja-build; yum clean all
