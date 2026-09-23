import unittest

from performance_compare import compare_pairs
from benchmark_compare import _stable_cli_findrefs_answer, should_gate


class PerformanceComparisonTests(unittest.TestCase):
    def test_cli_findrefs_answer_ignores_only_matched_payload_text(self):
        base = 'classes.dex | Lfoo/Bar;->run | matched=(truncated)'
        candidate = 'classes.dex | Lfoo/Bar;->run | matched=(full payload)'
        self.assertEqual(
            _stable_cli_findrefs_answer(base),
            _stable_cli_findrefs_answer(candidate),
        )
        self.assertNotEqual(
            _stable_cli_findrefs_answer(base),
            _stable_cli_findrefs_answer(
                'classes.dex | Lfoo/Baz;->run | matched=(full payload)'
            ),
        )

    def test_consistent_small_regression_is_reported_but_not_gated(self):
        result = compare_pairs([100.] * 31, [100.1] * 31, 26)
        self.assertTrue(result['statistically_significant'])
        self.assertFalse(result['material_slowdown'])
        self.assertFalse(result['regression'])

    def test_consistent_large_regression_fails(self):
        result = compare_pairs([100.] * 31, [200.] * 31, 26)
        self.assertTrue(result['statistically_significant'])
        self.assertTrue(result['material_slowdown'])
        self.assertTrue(result['regression'])

    def test_effect_floor_is_inclusive(self):
        result = compare_pairs([100.] * 31, [103.] * 31, 26)
        self.assertTrue(result['regression'])

    def test_only_aggregate_method_locator_is_gated(self):
        result = compare_pairs([100.] * 31, [200.] * 31, 11)
        self.assertTrue(should_gate('unit/method_locator', result))
        self.assertFalse(should_gate('unit/method_locator_none_class', result))
        self.assertFalse(should_gate('unit/method_locator_fuzzy_class_only', result))

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
