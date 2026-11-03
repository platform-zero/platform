import copy
import unittest
from matrix_recovery_safety import require_source_unchanged, require_target_stopped


class MatrixRecoverySafetyTest(unittest.TestCase):
    def item(self):
        return {'Id': 'container-1', 'Name': '/p0v3-live-target-rtc',
                'Config': {'Labels': {'io.p0v3.private-deployment': 'target'}},
                'State': {'Running': False, 'Paused': False, 'Restarting': False,
                          'Status': 'exited', 'Pid': 0, 'StartedAt': 'original'}}

    def test_exact_owned_stopped_target(self):
        self.assertEqual({'rtc': 'container-1'}, require_target_stopped(['rtc'], {'rtc': self.item()}, 'target'))

    def test_incomplete_running_foreign_or_uncertain_target_denied(self):
        for items in ({}, {'other': self.item()}):
            with self.assertRaises(ValueError):
                require_target_stopped(['rtc'], items, 'target')
        with self.assertRaises(ValueError):
            require_target_stopped([], {}, 'target')
        for field, value in [('Running', True), ('Paused', True), ('Restarting', True), ('Status', 'unknown'), ('Pid', 42)]:
            item = self.item(); item['State'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                require_target_stopped(['rtc'], {'rtc': item}, 'target')
        for field, value in [('Name', 'foreign'), ('Id', '')]:
            item = self.item(); item[field] = value
            with self.assertRaises(ValueError):
                require_target_stopped(['rtc'], {'rtc': item}, 'target')
        item = self.item(); item['Config']['Labels'].clear()
        with self.assertRaises(ValueError):
            require_target_stopped(['rtc'], {'rtc': item}, 'target')

    def test_source_observations_must_preserve_original_container_and_start(self):
        before = {'rtc': self.item()}
        require_source_unchanged(before, copy.deepcopy(before))
        for after in ({}, {'other': self.item()}):
            with self.assertRaises(ValueError):
                require_source_unchanged(before, after)
        with self.assertRaises(ValueError):
            require_source_unchanged({}, {})
        for field, value in [('StartedAt', 'new'), ('Running', True)]:
            after = copy.deepcopy(before); after['rtc']['State'][field] = value
            with self.assertRaises(ValueError):
                require_source_unchanged(before, after)
        after = copy.deepcopy(before); after['rtc']['Id'] = 'replacement'
        with self.assertRaises(ValueError):
            require_source_unchanged(before, after)


if __name__ == '__main__':
    unittest.main()
