from setuptools import setup, find_packages

setup(
    name = 'Archive',
    version = '0.4dev',
    author = 'Gary Wilson Jr.',
    author_email = 'gary.wilson@gmail.com',
    maintainer = 'Bruno Binet',
    maintainer_email = 'bruno.binet@gmail.com',
    packages = find_packages(),
    url = 'https://github.com/bbinet/Archive',
    license = 'LICENSE.txt',
    description = ('Simple library that provides a common interface for'
                   ' extracting zip and tar archives.'),
    long_description = open('README.txt').read(),
    setup_requires = [ 'nose' ],
    tests_require = [ 'coverage' ],
)
