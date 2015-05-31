#!/bin/bash
cd /opt/bcs/bcs-mumble/src
. ../bin/activate

echo "__import__('brave.mumble.service').mumble.service.main()" | paster shell local.ini

