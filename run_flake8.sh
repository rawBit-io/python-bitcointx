#!/bin/sh

exec flake8 --ignore E501,E221,E226,W503,W504 --exclude "./doc/*"
