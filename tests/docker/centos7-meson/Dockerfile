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
RUN yum -y install git gtk-doc gnutls-devel gupnp-igd-devel gstreamer1-devel gobject-introspection-devel valgrind net-tools centos-release-scl graphviz

ADD pip-installs.sh /
RUN bash -ex /pip-installs.sh && rm /pip-installs.sh
