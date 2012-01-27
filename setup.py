from distutils.core import setup

setup(
    name = 'Archive',
    version = '0.2dev',
    author = 'Gary Wilson Jr.',
    author_email = 'gary.wilson@gmail.com',
    packages = ['archive', 'archive.test'],
    url = 'http://code.google.com/p/python-archive/',
    license = 'LICENSE.txt',
    description = ('Simple library that provides a common interface for'
                   ' extracting zip and tar archives.'),
    long_description = open('README.txt').read(),
)
