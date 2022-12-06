#!/bin/bash

OWNER=$1

GH=$(which gh)

if [ -z "$GH" ]
then
    echo "Github CLI is required for this script. Please go to https://cli.github.com/ to install a supported version for your platform"
    exit 1
fi

if [ -z "$OWNER" ]
then
    echo "Usage ./sync_fork.sh OWNER [branch_name]. OWNER is required"
    exit 1
fi

if [ -z "$2" ]
then
    $GH repo sync $OWNER/akd -b main
else
    echo "Overriding the branch to $2"
    $GH repo sync $OWNER/$2 -b main
fi
