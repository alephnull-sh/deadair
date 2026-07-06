#!/usr/bin/env python3
"""Simulate a scheduled detection rule against a source with ingest lag.

A rule runs at times 0, I, 2I, ... Each run at R queries events with @timestamp in
[R-P, R] that are already ingested by R. An event at time T becomes searchable at
T+L. We count how many events any run catches, across all phases relative to the
run schedule, and compare against the closed form catch rate  clamp((P-L)/I, 0, 1).

Result: with interval I and lookback P, a source with ingest lag L has catch rate
    C(L) = max(0, min(1, (P - L) / I)).
Reliable (C=1) requires L <= P - I. Beyond that, misses are silent and linear.
"""


def simulate(I, P, L, n_events=600_000):
    caught = 0
    for T in range(n_events):  # one event per second: dense across all phases
        m = ((T + P) // I) * I  # largest scheduled run time <= T+P
        if m >= T + L:          # that run is also after the event was ingested
            caught += 1
    return caught / n_events


def closed_form(I, P, L):
    return max(0.0, min(1.0, (P - L) / I))


if __name__ == "__main__":
    I, P = 300, 360  # interval 5m, lookback 6m -> reliable margin P-I = 1m
    print(f"rule: interval {I//60}m, lookback {P//60}m, reliable margin {(P-I)//60}m\n")
    print(f"{'lag':>6} | {'closed form':>11} | {'simulated':>9}")
    print("-" * 34)
    for L in (30, 90, 180, 300, 360, 480):
        print(f"{L/60:>5}m | {closed_form(I,P,L)*100:>10.1f}% | {simulate(I,P,L)*100:>8.1f}%")
