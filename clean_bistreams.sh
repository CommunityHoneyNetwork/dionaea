#!/bin/bash

# Compress bistream files older than 5 minutes
find /opt/dionaea/var/dionaea/bistreams/* -type f -mmin +5 -exec gzip {} \;

# Clear bistream logs from dionaea every 60 minutes
find /opt/dionaea/var/dionaea/bistreams/* -type f -mtime +60 -exec rm {} \;
find /opt/dionaea/var/dionaea/bistreams/* -type d -empty -delete
