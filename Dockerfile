FROM ubuntu:18.04

LABEL maintainer="Team Stingar <team-stingar@duke.edu>"
LABEL name="dionaea"
LABEL version="1.9.1"
LABEL release="1"
LABEL summary="Dionaea HoneyPot container"
LABEL description="Dionaea is meant to be a nepenthes successor, embedding python as scripting language, using libemu to detect shellcodes, supporting ipv6 and tls."
LABEL autoritative-source-url "https://github.com/CommunityHoneyNetwork/dionaea"
LABEL changelog-url="https://github.com/CommunityHoneyNetwork/dionaea/commits/master"

ENV DOCKER "yes"
ENV DEBIAN_FRONTEND "noninteractive"
ENV DIONAEA_VERSION "0.11.0"

COPY requirements.txt /opt/requirements.txt

# hadolint ignore=DL3008,DL3005
RUN apt-get update && apt-get upgrade -y && \
    apt-get install --no-install-recommends -y \
      authbind \
      curl \
      cron \
      runit \
      git \
      python3-virtualenv \
      autoconf \
      automake \
      authbind \
      check \
      libtool \
      build-essential \
      cmake \
      check \
      cython3 \
      libcurl4-openssl-dev \
      libemu-dev \
      libev-dev \
      libglib2.0-dev \
      libloudmouth1-dev \
      libnetfilter-queue-dev \
      libnl-3-dev \
      libpcap-dev \
      libssl-dev \
      libtool \
      libudns-dev \
      jq \
      python3 \
      python3-dev \
      python3-bson \
      python3-yaml \
      python3-boto3 \
      python3-setuptools \
      python3-pip \
      ttf-mscorefonts-installer && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -s /bin/bash dionaea && \
    python3 -m pip install -r /opt/requirements.txt && \
    git clone https://github.com/dinotools/dionaea.git --branch ${DIONAEA_VERSION} /code && \
    mkdir -p /code/build

WORKDIR /code/build
RUN cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea .. && make && make install

COPY outputs/hpfeeds.py /opt/dionaea/lib/dionaea/python/dionaea/hpfeeds.py
COPY ihandlers-available/ /opt/ihandlers-available
RUN chown -R dionaea:root /opt/dionaea && \
    chown -R nobody:nogroup /opt/dionaea/var/log
COPY scripts /opt/scripts
COPY personalities /opt/personalities
COPY dionaea.cfg.orig /opt/dionaea/etc/dionaea/dionaea.cfg.orig
COPY entrypoint.sh /opt/entrypoint.sh
WORKDIR /opt

ENTRYPOINT ["/opt/entrypoint.sh"]
