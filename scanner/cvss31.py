"""
scanner/cvss31.py
=================
CVSS v3.1 Base Score calculator.

Purpose
-------
AlanScan stores CVSS vectors in config metadata. This module calculates
the CVSS v3.1 Base Score from a vector string so reports are consistent
and defensible (enterprise-grade output).
"""

from __future__ import annotations

import math
from dataclasses import dataclass


class CVSSVectorError(ValueError):
    pass


@dataclass(frozen=True)
class CVSSBaseResult:
    score: float
    vector: str


def _round_up_1_decimal(x: float) -> float:
    return math.ceil(x * 10.0) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    if not vector:
        raise CVSSVectorError("Empty CVSS vector")
    v = vector.strip()
    if v.startswith("CVSS:3.1/"):
        v = v[len("CVSS:3.1/") :]
    elif v.startswith("CVSS:3.0/"):
        # treat 3.0 as compatible for base metrics
        v = v[len("CVSS:3.0/") :]
    parts = [p for p in v.split("/") if p]
    metrics: dict[str, str] = {}
    for p in parts:
        if ":" not in p:
            raise CVSSVectorError(f"Invalid metric fragment: {p!r}")
        k, val = p.split(":", 1)
        metrics[k.upper()] = val.upper()
    return metrics


def calculate_base_score(vector: str) -> CVSSBaseResult:
    m = parse_vector(vector)

    # Required base metrics
    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    missing = [k for k in required if k not in m]
    if missing:
        raise CVSSVectorError(f"Missing base metric(s): {', '.join(missing)}")

    AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
    AC = {"L": 0.77, "H": 0.44}[m["AC"]]

    S = m["S"]
    PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
    PR = (PR_C if S == "C" else PR_U)[m["PR"]]

    UI = {"N": 0.85, "R": 0.62}[m["UI"]]

    C = {"H": 0.56, "L": 0.22, "N": 0.0}[m["C"]]
    I = {"H": 0.56, "L": 0.22, "N": 0.0}[m["I"]]
    A = {"H": 0.56, "L": 0.22, "N": 0.0}[m["A"]]

    exploitability = 8.22 * AV * AC * PR * UI
    iss = 1.0 - ((1.0 - C) * (1.0 - I) * (1.0 - A))

    if S == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    if impact <= 0:
        score = 0.0
    else:
        if S == "U":
            score = min(impact + exploitability, 10.0)
        else:
            score = min(1.08 * (impact + exploitability), 10.0)
        score = _round_up_1_decimal(score)

    # Always normalize to CVSS:3.1 prefix for output
    normalized = "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in required)
    return CVSSBaseResult(score=float(score), vector=normalized)

