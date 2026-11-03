"""Finalize probe evidence without allowing an earlier sub-probe pass to hide a later failure."""
from contextlib import contextmanager


@contextmanager
def private_receipt(receipt, persist):
    try:
        yield receipt
    except BaseException:
        receipt['passed'] = False
        raise
    finally:
        try:
            persist(receipt)
        except BaseException:
            receipt['passed'] = False
            raise
