"""Paired performance checks with a minimum practical slowdown threshold."""
import math
import statistics


def compare_pairs(base, candidate, metric_count, alpha=0.05, effect_floor_percent=3.0):
    if len(base) != len(candidate) or len(base) < 15:
        raise ValueError('at least 15 complete paired samples are required')
    if metric_count < 1 or not 0 < alpha < 1 or effect_floor_percent < 0:
        raise ValueError('invalid comparison parameters')
    if any(not math.isfinite(value) or value <= 0 for value in base + candidate):
        raise ValueError('timings must be finite and positive')
    ratios = [new / old for old, new in zip(base, candidate)]
    slower = sum(value > 1 for value in ratios)
    faster = sum(value < 1 for value in ratios)
    n = slower + faster
    p_value = sum(math.comb(n, k) for k in range(slower, n + 1)) / 2 ** n
    threshold = alpha / metric_count
    paired_median_change_percent = (statistics.median(ratios) - 1) * 100
    statistically_significant = p_value < threshold
    material_slowdown = paired_median_change_percent >= effect_floor_percent
    return {'base_median': statistics.median(base),
            'candidate_median': statistics.median(candidate),
            'paired_median_change_percent': paired_median_change_percent,
            'slower_pairs': slower, 'faster_pairs': faster,
            'p_value': p_value, 'threshold': threshold,
            'effect_floor_percent': effect_floor_percent,
            'statistically_significant': statistically_significant,
            'material_slowdown': material_slowdown,
            'regression': statistically_significant and material_slowdown}
