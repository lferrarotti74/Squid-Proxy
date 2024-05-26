#!/bin/sh

nc -z localhost 3128; nccode=$?

if [ $nccode -eq 0 ]; then
    exit 0  # Service is running, healthcheck passes
else
    exit 1  # Something is wrong, not all healthchecks are okay
fi
