#!/bin/bash
cd /opt/bcs/bcs-mumble/src
. ../bin/activate

echo "__import__('brave.mumble.service').mumble.service.main('ICE_SECRET_WRITE')" | paster shell local.ini

