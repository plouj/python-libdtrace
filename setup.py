from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

ext_modules = [
    Extension("dtrace",
              ["dtrace.pyx"],
              libraries=["dtrace"]) # Unix-like specific
]

setup(
  name = 'Dtrace Python wrapper',
  cmdclass = {'build_ext': build_ext},
  ext_modules = ext_modules
)
