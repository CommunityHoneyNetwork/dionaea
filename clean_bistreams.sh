#!/bin/bash

# Compress bistream files older than 1 hour
find /opt/dionaea/var/dionaea/bistreams/* -type f -mmin +5 -exec gzip {} \;

# Clear bistream logs from dionaea every day
find /opt/dionaea/var/dionaea/bistreams/* -type f -mtime +60 -exec rm {} \;
find /opt/dionaea/var/dionaea/bistreams/* -type d -empty -delete
