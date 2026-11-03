import importlib.util
import io
from pathlib import Path
import unittest
import zipfile

spec=importlib.util.spec_from_file_location('office_probe',Path(__file__).with_name('test-private-office.py'))
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)

class OfficeFixtureTest(unittest.TestCase):
    def test_synthetic_docx_has_native_package_relationships_and_text(self):
        data=probe.document()
        self.assertEqual(probe.text(data),'Synthetic private office document.')
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            self.assertEqual(set(archive.namelist()),{'[Content_Types].xml','_rels/.rels','word/document.xml'})
            self.assertIn(b'word/document.xml',archive.read('_rels/.rels'))
    def test_readback_refuses_excessive_entries_or_expansion(self):
        for entries,size in ((501,1),(1,10*1024*1024+1)):
            data=io.BytesIO()
            with zipfile.ZipFile(data,'w',zipfile.ZIP_DEFLATED) as archive:
                for n in range(entries):archive.writestr(str(n),b'x'*size)
            with self.assertRaises(AssertionError):probe.text(data.getvalue())

if __name__=='__main__':unittest.main()
