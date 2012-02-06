import os
import shutil
import tempfile
import unittest

from archive import Archive, extract, UnsafeArchive, UnrecognizedArchiveFormat


TEST_DIR = os.path.dirname(os.path.abspath(__file__))


class BaseArchiveTester(object):
    archive = None

    def setUp(self):
        """
        Create temporary directory for testing extraction.
        """
        self.tmpdir = tempfile.mkdtemp()
        self.archive_path = os.path.join(TEST_DIR, self.archive)
        # Always start off in TEST_DIR.
        os.chdir(TEST_DIR)

    def tearDown(self):
        """
        Clean up temporary directory.
        """
        shutil.rmtree(self.tmpdir)

    def check_files(self, tmpdir):
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, '1')))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, '2')))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, 'foo', '1')))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, 'foo', '2')))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, 'foo', 'bar', '1')))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, 'foo', 'bar', '2')))


class ArchiveTester(BaseArchiveTester):

    def test_extract_method(self):
        Archive(self.archive).extract(self.tmpdir)
        self.check_files(self.tmpdir)

    def test_extract_method_fileobject(self):
        f = open(self.archive)
        Archive(f).extract(self.tmpdir)
        self.check_files(self.tmpdir)

    def test_extract_method_no_to_path(self):
        os.chdir(self.tmpdir)
        Archive(self.archive_path).extract()
        self.check_files(self.tmpdir)

    def test_extract_function(self):
        extract(self.archive_path, self.tmpdir)
        self.check_files(self.tmpdir)

    def test_extract_function_fileobject(self):
        f = open(self.archive_path)
        extract(f, self.tmpdir)
        self.check_files(self.tmpdir)

    def test_extract_function_no_to_path(self):
        os.chdir(self.tmpdir)
        extract(self.archive_path)
        self.check_files(self.tmpdir)

    def test_namelist_method(self):
        l = Archive(self.archive).namelist()
        expected = [
                '1',
                '2',
                'foo',
                'foo/1',
                'foo/2',
                'foo/bar',
                'foo/bar/1',
                'foo/bar/2']
        if self.archive != 'foobar.zip':
            # namelist result contains '.' except for the zip file
            expected.insert(0, '.')
        self.assertEqual([os.path.relpath(p) for p in l], expected)


class EvilArchiveTester(BaseArchiveTester):

    def test_extract_method(self):
        self.assertRaises(UnsafeArchive, Archive(self.archive).extract,
                self.tmpdir, safe=True)

    def test_extract_method_fileobject(self):
        f = open(self.archive)
        self.assertRaises(UnsafeArchive, Archive(f).extract, self.tmpdir,
                safe=True)

    def test_extract_method_no_to_path(self):
        os.chdir(self.tmpdir)
        self.assertRaises(UnsafeArchive, Archive(self.archive_path).extract,
                safe=True)

    def test_extract_function(self):
        self.assertRaises(UnsafeArchive, extract, self.archive_path,
                self.tmpdir, safe=True)

    def test_extract_function_fileobject(self):
        f = open(self.archive_path)
        self.assertRaises(UnsafeArchive, extract, f, self.tmpdir, safe=True)

    def test_extract_function_no_to_path(self):
        os.chdir(self.tmpdir)
        self.assertRaises(UnsafeArchive, extract, self.archive_path, safe=True)

    def test_namelist_method(self):
        l = Archive(self.archive).namelist()
        expected = ['../../../../../../etc/passwd']
        self.assertEqual([os.path.relpath(p) for p in l], expected)



class NoExtArchiveTester(BaseArchiveTester):

    def test_constructor(self):
        self.assertRaises(UnrecognizedArchiveFormat, Archive, self.archive)

    def test_extract_method_filename(self):
        Archive(self.archive, filename=self.filename).extract(self.tmpdir)
        self.check_files(self.tmpdir)

    def test_extract_function_filename(self):
        extract(self.archive_path, self.tmpdir, filename=self.filename)
        self.check_files(self.tmpdir)


class TestZip(ArchiveTester, unittest.TestCase):
    archive = 'foobar.zip'


class TestEvilZip(EvilArchiveTester, unittest.TestCase):
    archive = 'evil.zip'


class TestTar(ArchiveTester, unittest.TestCase):
    archive = 'foobar.tar'


class TestGzipTar(ArchiveTester, unittest.TestCase):
    archive = 'foobar.tar.gz'


class TestGzipTarNoExt(NoExtArchiveTester, unittest.TestCase):
    archive = 'foobar_targz'
    filename = 'foobar.tar.gz'


class TestZipNoExt(NoExtArchiveTester, unittest.TestCase):
    archive = 'foobar_zip'
    filename = 'foobar.zip'


class TestEvilGzipTar(EvilArchiveTester, unittest.TestCase):
    archive = 'evil.tar.gz'


class TestBzip2Tar(ArchiveTester, unittest.TestCase):
    archive = 'foobar.tar.bz2'
