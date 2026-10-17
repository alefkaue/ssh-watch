import unittest
from ssh_watch import analyze

def line(second, kind='Failed', ip='192.0.2.1'):
    return f'2026-01-01T00:00:{second:02d}Z host sshd: {kind} password for root from {ip} port 22 ssh2'

class DetectionTests(unittest.TestCase):
    def test_burst_and_success_with_evidence(self):
        report = analyze([line(0), line(1), line(2, 'Accepted')], 2)
        self.assertEqual([x['type'] for x in report['findings']], ['ssh_failure_burst', 'ssh_success_after_failures'])
        self.assertEqual(report['findings'][1]['evidence_lines'], [1, 2, 3])

    def test_expiry_and_separate_addresses(self):
        self.assertEqual(analyze([line(0), line(30), line(31, ip='192.0.2.2')], 2, 10)['findings'], [])

    def test_unsorted_input_and_inclusive_boundary(self):
        self.assertEqual(len(analyze([line(10), line(0)], 2, 10)['findings']), 1)

    def test_malformed_and_timezone_missing(self):
        report = analyze(['garbage', line(0, ip='bad'), line(0).replace('Z', '')])
        self.assertEqual(report['ignored_lines'], 3)

    def test_no_duplicate_burst(self):
        self.assertEqual(len(analyze([line(i) for i in range(5)], 2)['findings']), 1)

    def test_ipv6_and_invalid_options(self):
        self.assertEqual(len(analyze([line(0, ip='2001:db8::1'), line(1, ip='2001:db8::1')], 2)['findings']), 1)
        with self.assertRaises(ValueError):
            analyze([], 1)
