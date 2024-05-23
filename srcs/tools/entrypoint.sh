#!/bin/bash

cd $MYAPP

if [[ -f "manage.py" ]];
then
    echo found
else
    django-admin startproject $MYAPP .
fi

exec "$@"
