from distutils.core import setup
from distutils.extension import Extension

mycmdclass = {}

try:
    from Cython.Distutils import build_ext
except ImportError:
    print "cython not found, using a previously-cython'd .c file."
    ext_modules = [
        Extension("dtrace",
                  ["dtrace.c"],
                  libraries=["dtrace"])
        ]
else:
    ext_modules = [
        Extension("dtrace",
                  ["dtrace.pyx"],
                  libraries=["dtrace"])
        ]
    mycmdclass['build_ext'] = build_ext

setup(
    name = 'Dtrace Python wrapper',
    cmdclass = mycmdclass,
    ext_modules = ext_modules
    )
