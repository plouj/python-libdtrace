python-libdtrace
================

This is a Python binding to DTrace.

The code has been greatly inspired by the NodeJS binding
(https://github.com/bcantrill/node-libdtrace) and currently supports
an even smaller subset of functionality.


Testing
------------

First install Cython (http://cython.org/)

Then compile the module:

  $ python setup.py build_ext --inplace

This will put dtrace and dtrace.so in the current directory.

Finally run the test script:

  $ sudo python test.py

Python will pickup dtrace.so from the current directory and import it
as a regular module.