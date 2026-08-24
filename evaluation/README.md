# Evaluation — public de-identified reproducibility workflow

This folder lets you inspect and re-run the **public, de-identified** scoring
workflow behind SecretSifter's benchmark comparison: the scoring script, the
detection matrix it reads, the six-rule overlay applied to the rule-extensible
scanners, and the per-tool run commands.

## What this reproduces (and what it does not)

There are two related but distinct result sets. Read this before running the
script, so the numbers are not mistaken for one another.

| | This folder | SoftwareX Table 2 |
|---|---|---|
| Corpus | 161-row **static subset**, de-identified | full **198-value** benchmark |
| Configuration | **tightened** (six-rule overlay) | **default** per-tool configuration |
| Values | identifiers removed; value column does not exist | confidential production values |
| Redistributable | yes, CC BY 4.0 | no (single-organization confidentiality) |
| Source | companion reproducibility bundle | manuscript |

So `score.py` reproduces the **tightened-configuration figures over the 161
static-subset** (SecretSifter 121/161, TruffleHog 107/161, and so on) that were
published in the companion study's de-identified bundle. It does **not**
reproduce the SoftwareX manuscript's Table 2, whose default-configuration
numbers over the full 198-value benchmark are computed against confidential
production values that cannot be redistributed. The two are complementary: the
198-value default-config numbers are the headline evaluation; the 161-static
tightened-config numbers here are the robustness view that can be released in
full.

## Run it

```
python3 evaluation/score.py     # from the repository root
python3 score.py                # from inside this folder
```

No dependencies (Python 3.8+); the script finds the CSV next to itself, so it
runs from either directory. Expected output includes:

```
SecretSifter    121   75.2%
TruffleHog      107   66.5%
Nuclei           99   61.5%
JSluice          96   59.6%
...
Tool-agnostic blind spot (missed by all 9 scanners): 14/161 = 8.7%
```

## Files

| File | Contents |
|---|---|
| [`score.py`](score.py) | Reads the matrix, prints per-tool recall, blind spot, and the SecretSifter-alone count. |
| [`detection_matrix_deidentified_161.csv`](detection_matrix_deidentified_161.csv) | 161 static-subset credentials x 10 detectors, binary outcomes. No values, key names, domains, paths, or environment labels. |
| [`six_rule_overlay.yaml`](six_rule_overlay.yaml) | The six regex rules applied identically to TruffleHog, SecretFinder, Titus, and JSluice. |
| [`commands.md`](commands.md) | Per-tool invocations and configuration notes. |
| [`DATA_LICENSE_CC-BY-4.0.txt`](DATA_LICENSE_CC-BY-4.0.txt) | License for the data files (CC BY 4.0). |

The `score.py` and `commands.md` files are covered by this repository's MIT
license; the CSV and the overlay are the de-identified research data, released
under CC BY 4.0.

## Matrix columns

`idx`, `app_anon` (anonymized app IDs; 33 distinct apps appear in this static
matrix), `type`, `severity`, then ten binary detector columns
(`ClaudeOpus` … `Cariddi`), then `missed_by_all_scanners` and
`missed_by_all_except_secretsifter`. Each detector column is `1` if that detector
flagged the credential at actionable severity, else `0`. `ClaudeOpus` is the LLM
oracle used to build ground truth (a labeling reference, not a competing
detector). `missed_by_all_except_secretsifter` counts 50 rows, which split into
36 SecretSifter-alone detections and the 14 tool-agnostic blind-spot rows.

## Full protocol and configurations

The complete evaluation protocol, the full per-tool configurations, the
significance testing (45-pair Holm-corrected McNemar), and the detection-set
overlap analysis are reported in the companion study and its appendices, and the
full de-identified artifact set (including the significance tables) is archived
at <https://doi.org/10.5281/zenodo.21695364>.
