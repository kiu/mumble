#!/bin/bash
cd /opt/bcs/bcs-mumble/src
. ../bin/activate
paster serve local.ini
