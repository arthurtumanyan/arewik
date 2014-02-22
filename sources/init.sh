#!/bin/bash
aclocal  && \
libtoolize --automake && \
autoheader && \
automake --foreign --add-missing && \
autoconf
