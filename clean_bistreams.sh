#!/bin/bash

CURRENT=$(df / | grep / | awk '{ print $5 }' | sed 's/%//g')
THRESHOLD=95

# Compress bistream files older than 5 minutes
find /opt/dionaea/var/dionaea/bistreams/* -type f -mmin +5 -exec gzip {} \;

if [ "${CURRENT}" -gt "${THRESHOLD}" ] ; then
  # Clear all bistream logs from dionaea if disk nearly full
  find /opt/dionaea/var/dionaea/bistreams/* -type f -exec rm {} \;
else
  # Clear bistream logs from dionaea every 60 minutes
  find /opt/dionaea/var/dionaea/bistreams/* -type f -mmin +60 -exec rm {} \;
fi

find /opt/dionaea/var/dionaea/bistreams/* -type d -empty -delete
