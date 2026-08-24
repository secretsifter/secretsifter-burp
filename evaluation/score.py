#!/usr/bin/env python3
"""
Score the public de-identified detection matrix.

Reads detection_matrix_deidentified_161.csv (161 static-subset credentials x 10
detectors, de-identified) and reports per-tool recall over the static subset,
the tool-agnostic blind spot, and the SecretSifter-alone count.

IMPORTANT — what this reproduces:
  These are the tightened-configuration figures over the 161-row STATIC SUBSET
  of the benchmark, as published in the companion study's de-identified
  reproducibility bundle. They are NOT the SoftwareX manuscript's Table 2, which
  reports the default-configuration evaluation over the full 198-value benchmark
  against confidential production values that are not redistributable. See
  README.md for the distinction.

Usage:
  python3 score.py
  python3 score.py --csv detection_matrix_deidentified_161.csv

No third-party dependencies. Python 3.8+.
"""
import argparse
import csv
import sys
from pathlib import Path

# The ten detector columns, in matrix order. ClaudeOpus is the LLM oracle /
# labeling reference, not a competing scanner, and is reported separately.
ORACLE = "ClaudeOpus"
SCANNERS = [
    "SecretSifter", "TruffleHog", "Nuclei", "JSluice", "SecretFinder",
    "Titus", "JSMiner", "SensitiveDiscoverer", "Cariddi",
]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    default_csv = Path(__file__).resolve().parent / "detection_matrix_deidentified_161.csv"
    ap.add_argument("--csv", default=str(default_csv),
                    help="path to the de-identified detection matrix "
                         "(defaults to the CSV next to this script)")
    args = ap.parse_args()

    try:
        with open(args.csv, newline="") as fh:
            rows = list(csv.DictReader(fh))
    except FileNotFoundError:
        sys.exit(f"error: cannot find {args.csv}")

    n = len(rows)
    if n == 0:
        sys.exit("error: matrix is empty")

    # Per-scanner recall = column sum / n.
    hits = {s: sum(int(r[s]) for r in rows) for s in SCANNERS}
    oracle_hits = sum(int(r[ORACLE]) for r in rows)

    blind = sum(int(r["missed_by_all_scanners"]) for r in rows)
    except_ss = sum(int(r["missed_by_all_except_secretsifter"]) for r in rows)
    ss_alone = sum(1 for r in rows
                   if int(r["missed_by_all_except_secretsifter"]) == 1
                   and int(r["SecretSifter"]) == 1)

    print(f"De-identified static subset: n = {n} credentials\n")
    print(f"  {'Detector':<22}{'Hits':>6}{'Recall':>10}")
    print(f"  {'-' * 38}")
    for s in sorted(SCANNERS, key=lambda x: hits[x], reverse=True):
        print(f"  {s:<22}{hits[s]:>6}{hits[s] / n:>9.1%}")
    print(f"  {'-' * 38}")
    print(f"  {ORACLE + ' (oracle)':<22}{oracle_hits:>6}{oracle_hits / n:>9.1%}"
          f"   (labeling reference, not a scanner)\n")

    print(f"  Tool-agnostic blind spot (missed by all 9 scanners): "
          f"{blind}/{n} = {blind / n:.1%}")
    print(f"  Union coverage (at least one scanner):               "
          f"{n - blind}/{n} = {(n - blind) / n:.1%}")
    print(f"  Missed by every scanner except SecretSifter:         "
          f"{except_ss}  (= {ss_alone} SecretSifter-alone + {blind} blind spot)")


if __name__ == "__main__":
    main()
