import unittest
from mail_fixture_selection import select_fixture_uid


class MailSelectionTest(unittest.TestCase):
    def header(self, subject='Private mail nonce', mid='<nonce@example.org>'):
        return ('Subject: ' + subject + '\r\nMessage-ID: ' + mid + '\r\n\r\n').encode()
    def select(self, candidates):
        return select_fixture_uid(candidates, 'Private mail nonce', '<nonce@example.org>')
    def test_exact_headers_not_token_candidate_count(self):
        self.assertEqual(self.select([(b'2', self.header('Private SOGo mail nonce')), (b'1', self.header())]), b'1')
        self.assertIsNone(self.select([(b'2', self.header('Other message'))]))
        self.assertIsNone(self.select([]))
    def test_duplicate_identity_and_subject_fail_closed(self):
        for candidates in (
            [(b'1', self.header()), (b'2', self.header())],
            [(b'1', self.header()), (b'1', self.header())],
            [(b'1', self.header(mid='<different@example.org>'))],
            [(b'1', b'Subject: Private mail nonce\r\nSubject: Private mail nonce\r\nMessage-ID: <nonce@example.org>\r\n\r\n')],
            [(b'1', b'Subject: Private mail nonce\r\n\r\n')],
        ):
            with self.assertRaises(ValueError):
                self.select(candidates)
    def test_bounds_and_malformed_headers(self):
        for candidates in (
            [(str(i + 1).encode(), self.header('Other')) for i in range(33)],
            [(b'0', self.header())], [(b'uid', self.header())], [(b'1', b'x' * 16385)], [(b'1', b'not a header\r\n')],
        ):
            with self.assertRaises(ValueError):
                self.select(candidates)


if __name__ == '__main__':
    unittest.main()
