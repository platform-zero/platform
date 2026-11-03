import unittest
from probe_receipt import private_receipt


class PrivateReceiptTest(unittest.TestCase):
    def test_success_requires_explicit_completion(self):
        saved=[];record={'passed':False}
        with private_receipt(record,lambda r:saved.append(dict(r))):
            pass
        self.assertFalse(saved[0]['passed'])
        with private_receipt(record,lambda r:saved.append(dict(r))):
            record.update(passed=True,phase='complete')
        self.assertTrue(saved[-1]['passed'])

    def test_late_failure_overrides_subprobe_pass(self):
        saved=[];record={'passed':False}
        with self.assertRaisesRegex(RuntimeError,'later check'):
            with private_receipt(record,lambda r:saved.append(dict(r))):
                record.update(passed=True,phase='restart')
                raise RuntimeError('later check failed')
        self.assertFalse(saved[0]['passed'])
        self.assertEqual(saved[0]['phase'],'restart')

    def test_interrupt_is_not_success(self):
        saved=[];record={'passed':True}
        with self.assertRaises(KeyboardInterrupt):
            with private_receipt(record,lambda r:saved.append(dict(r))):
                raise KeyboardInterrupt()
        self.assertFalse(saved[0]['passed'])

    def test_persistence_failure_cannot_return_success(self):
        record={'passed':True}
        def broken(_):raise OSError('not persisted')
        with self.assertRaises(OSError):
            with private_receipt(record,broken):
                pass
        self.assertFalse(record['passed'])


if __name__=='__main__':unittest.main()
