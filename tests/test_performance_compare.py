import unittest

from performance_compare import compare_pairs


class PerformanceComparisonTests(unittest.TestCase):
    def test_consistent_small_regression_fails(self):
        self.assertTrue(compare_pairs([100.] * 31, [100.1] * 31, 26)['regression'])

    def test_consistent_large_regression_fails(self):
        self.assertTrue(compare_pairs([100.] * 31, [200.] * 31, 26)['regression'])

    def test_improvement_and_equal_times_pass(self):
        for value in (50., 100.):
            self.assertFalse(compare_pairs([100.] * 31, [value] * 31, 26)['regression'])

    def test_balanced_noise_does_not_fail(self):
        values = [90., 110.] * 15 + [100.]
        self.assertFalse(compare_pairs([100.] * 31, values, 26)['regression'])

    def test_single_outlier_does_not_fail(self):
        values = [100.] * 30 + [10000.]
        self.assertFalse(compare_pairs([100.] * 31, values, 26)['regression'])

    def test_missing_or_invalid_measurements_fail(self):
        for values in ([], [100.] * 30, [float('nan')] * 31, [0.] * 31):
            with self.assertRaises(ValueError):
                compare_pairs([100.] * 31, values, 26)
