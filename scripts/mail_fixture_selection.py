"""Bounded exact-header selection after native indexed IMAP candidate search."""
from email import policy
from email.parser import BytesParser
import re


def select_fixture_uid(candidates, subject, message_id):
    if len(candidates) > 32:
        raise ValueError('Too many indexed mail candidates')
    seen, matching = set(), []
    for uid, raw_headers in candidates:
        if not re.fullmatch(rb'[1-9][0-9]{0,19}', uid) or uid in seen or len(raw_headers) > 16384:
            raise ValueError('Invalid, repeated or oversized mail candidate')
        seen.add(uid)
        headers = BytesParser(policy=policy.default).parsebytes(raw_headers, headersonly=True)
        if headers.defects:
            raise ValueError('Malformed native mail headers')
        subjects = headers.get_all('Subject', [])
        if subject in subjects:
            if subjects != [subject] or headers.get_all('Message-ID', []) != [message_id]:
                raise ValueError('Exact fixture subject has unexpected identity headers')
            matching.append(uid)
    if len(matching) > 1:
        raise ValueError('Duplicate exact fixture messages; never select the first')
    return matching[0] if matching else None
