"""Paired zero-regression checks; no allowed percentage slowdown."""
import math
import statistics


def compare_pairs(base, candidate, metric_count, alpha=0.05):
    if len(base) != len(candidate) or len(base) < 15:
        raise ValueError('at least 15 complete paired samples are required')
    if metric_count < 1 or not 0 < alpha < 1:
        raise ValueError('invalid comparison parameters')
    if any(not math.isfinite(value) or value <= 0 for value in base + candidate):
        raise ValueError('timings must be finite and positive')
    ratios = [new / old for old, new in zip(base, candidate)]
    slower = sum(value > 1 for value in ratios)
    faster = sum(value < 1 for value in ratios)
    n = slower + faster
    p_value = sum(math.comb(n, k) for k in range(slower, n + 1)) / 2 ** n
    threshold = alpha / metric_count
    return {'base_median': statistics.median(base),
            'candidate_median': statistics.median(candidate),
            'paired_median_change_percent': (statistics.median(ratios) - 1) * 100,
            'slower_pairs': slower, 'faster_pairs': faster,
            'p_value': p_value, 'threshold': threshold,
            'regression': p_value < threshold}
