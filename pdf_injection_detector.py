#!/usr/bin/env python3
"""
PDF Prompt Injection Detection Scanner (Blue Team Tool)
========================================================
Purpose: Scan PDF files for signs of prompt injection attacks using
         multiple detection heuristics across different attack vectors.

Author: Gaoxing Zhang
Source Code: https://github.com/zhihuiyuze/PDF-Prompt-Injection-Toolkit
"""

import os
import re
import sys
import json
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime

import pdfplumber
from pypdf import PdfReader
import pikepdf

# ============================================================
# Configuration: Detection Thresholds & Patterns
# ============================================================

# Suspicious prompt injection keywords/patterns
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"ignore\s+(all\s+)?prior\s+instructions",
    r"disregard\s+(all\s+)?(previous|prior|above)",
    r"you\s+are\s+now\s+a",
    r"new\s+instructions?\s*:",
    r"\[SYSTEM\]",
    r"\[INST\]",
    r"<\|system\|>",
    r"<\|user\|>",
    r"<\|assistant\|>",
    r"HIGHLY\s+RECOMMENDED",
    r"score\s*:\s*\d{2,3}\s*/\s*100",
    r"rate\s+this\s+candidate\s+as",
    r"override\s+(previous|all|system)",
    r"act\s+as\s+(if|though)",
    r"pretend\s+(you|that)",
    r"from\s+now\s+on",
    r"do\s+not\s+follow",
    r"reset\s+(your|all)\s+instructions",
]

# Font size threshold (points) below which text is suspicious
MICRO_FONT_THRESHOLD = 3.0

# Minimum contrast ratio for text to be considered visible
# (simplified: checks if text color is too close to white)
WHITE_COLOR_THRESHOLD = 0.90  # RGB values above this are "near-white"

# Zero-width and invisible Unicode character ranges
INVISIBLE_CHARS = {
    "\u200B": "Zero-Width Space (U+200B)",
    "\u200C": "Zero-Width Non-Joiner (U+200C)",
    "\u200D": "Zero-Width Joiner (U+200D)",
    "\uFEFF": "Byte Order Mark / ZWNBSP (U+FEFF)",
    "\u00AD": "Soft Hyphen (U+00AD)",
    "\u200E": "Left-to-Right Mark (U+200E)",
    "\u200F": "Right-to-Left Mark (U+200F)",
    "\u2060": "Word Joiner (U+2060)",
    "\u2061": "Function Application (U+2061)",
    "\u2062": "Invisible Times (U+2062)",
    "\u2063": "Invisible Separator (U+2063)",
    "\u2064": "Invisible Plus (U+2064)",
    "\u180E": "Mongolian Vowel Separator (U+180E)",
}

# Unicode Tags block (U+E0000 - U+E007F) used for steganographic encoding
TAG_RANGE = range(0xE0000, 0xE0080)


# ============================================================
# Data Classes for Structured Results
# ============================================================
@dataclass
class Finding:
    technique: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    evidence: str = ""
    location: str = ""


@dataclass
class ScanReport:
    filepath: str
    scan_time: str = ""
    file_size: int = 0
    page_count: int = 0
    findings: list = field(default_factory=list)
    risk_score: int = 0  # 0-100
    risk_level: str = "CLEAN"

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def calculate_risk(self):
        severity_scores = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5, "INFO": 1}
        total = sum(severity_scores.get(f.severity, 0) for f in self.findings)
        self.risk_score = min(total, 100)
        if self.risk_score >= 60:
            self.risk_level = "CRITICAL"
        elif self.risk_score >= 40:
            self.risk_level = "HIGH"
        elif self.risk_score >= 20:
            self.risk_level = "MEDIUM"
        elif self.risk_score > 0:
            self.risk_level = "LOW"
        else:
            self.risk_level = "CLEAN"


# ============================================================
# Detection Module 1: Prompt Injection Pattern Matching
# ============================================================
def detect_injection_patterns(text: str, source: str = "body") -> list:
    """Scan text for known prompt injection patterns."""
    findings = []
    for pattern in INJECTION_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            # Find the actual matching substring for evidence
            match = re.search(pattern, text, re.IGNORECASE)
            snippet = text[max(0, match.start() - 20): match.end() + 20].strip()
            findings.append(Finding(
                technique="Prompt Injection Pattern",
                severity="CRITICAL",
                description=f"Detected injection keyword pattern in {source}: /{pattern}/",
                evidence=f"...{snippet}...",
                location=source,
            ))
    return findings


# ============================================================
# Detection Module 2: White/Invisible Text Detection
# ============================================================
def detect_invisible_text(filepath: str) -> list:
    """
    Detect text with suspicious visual properties:
    - White or near-white font color on white background
    - Extremely small font sizes (< threshold)
    """
    findings = []
    try:
        with pdfplumber.open(filepath) as pdf:
            for page_num, page in enumerate(pdf.pages, 1):
                chars = page.chars
                for char in chars:
                    text_char = char.get("text", "")
                    if not text_char.strip():
                        continue

                    # --- Check font size ---
                    font_size = char.get("size", 12)
                    if font_size is not None and font_size < MICRO_FONT_THRESHOLD:
                        findings.append(Finding(
                            technique="Micro Font Injection",
                            severity="HIGH",
                            description=f"Text with extremely small font size ({font_size:.1f}pt) detected",
                            evidence=f"Char: '{text_char}' at size {font_size:.1f}pt",
                            location=f"Page {page_num}, pos ({char.get('x0', '?'):.0f}, {char.get('top', '?'):.0f})",
                        ))
                        break  # One finding per page is enough

                    # --- Check color (near-white detection) ---
                    # pdfplumber stores colors in various formats
                    color = char.get("non_stroking_color")
                    if color and _is_near_white(color):
                        findings.append(Finding(
                            technique="White Text Injection",
                            severity="HIGH",
                            description=f"Text with near-white color detected (likely hidden)",
                            evidence=f"Char: '{text_char}', color: {color}",
                            location=f"Page {page_num}, pos ({char.get('x0', '?'):.0f}, {char.get('top', '?'):.0f})",
                        ))
                        break  # One finding per page is enough

    except Exception as e:
        findings.append(Finding(
            technique="Scan Error",
            severity="INFO",
            description=f"Could not analyze character properties: {e}",
        ))
    return findings


def _is_near_white(color) -> bool:
    """Check if a color value is near-white (invisible on white background)."""
    if color is None:
        return False
    try:
        if isinstance(color, (list, tuple)):
            if len(color) == 3:  # RGB
                return all(c >= WHITE_COLOR_THRESHOLD for c in color)
            elif len(color) == 4:  # CMYK
                return all(c <= (1 - WHITE_COLOR_THRESHOLD) for c in color)
            elif len(color) == 1:  # Grayscale
                return color[0] >= WHITE_COLOR_THRESHOLD
        elif isinstance(color, (int, float)):
            return color >= WHITE_COLOR_THRESHOLD
    except (TypeError, IndexError):
        pass
    return False


# ============================================================
# Detection Module 3: Metadata Injection Detection
# ============================================================
def detect_metadata_injection(filepath: str) -> list:
    """Scan PDF metadata fields for prompt injection payloads."""
    findings = []
    try:
        reader = PdfReader(filepath)
        meta = reader.metadata
        if meta:
            meta_fields = {
                "Title": meta.title,
                "Author": meta.author,
                "Subject": meta.subject,
                "Creator": meta.creator,
                "Producer": meta.producer,
            }
            for field_name, value in meta_fields.items():
                if value and len(str(value)) > 0:
                    pattern_findings = detect_injection_patterns(
                        str(value), source=f"Metadata/{field_name}"
                    )
                    findings.extend(pattern_findings)

                    # Also flag unusually long metadata
                    if len(str(value)) > 200:
                        findings.append(Finding(
                            technique="Suspicious Metadata",
                            severity="MEDIUM",
                            description=f"Metadata field '{field_name}' is unusually long ({len(str(value))} chars)",
                            evidence=str(value)[:100] + "...",
                            location=f"Metadata/{field_name}",
                        ))

        # Also check XMP metadata with pikepdf
        with pikepdf.open(filepath) as pdf:
            try:
                with pdf.open_metadata() as xmp:
                    xmp_str = str(xmp)
                    if xmp_str:
                        xmp_findings = detect_injection_patterns(
                            xmp_str, source="XMP Metadata"
                        )
                        findings.extend(xmp_findings)
            except Exception:
                pass

            # Check DocumentInfo dictionary
            if pdf.docinfo:
                for key, value in pdf.docinfo.items():
                    val_str = str(value)
                    if val_str:
                        di_findings = detect_injection_patterns(
                            val_str, source=f"DocumentInfo{key}"
                        )
                        findings.extend(di_findings)

    except Exception as e:
        findings.append(Finding(
            technique="Scan Error",
            severity="INFO",
            description=f"Metadata scan error: {e}",
        ))
    return findings


# ============================================================
# Detection Module 4: Off-Page / Out-of-Bounds Text Detection
# ============================================================
def detect_offpage_text(filepath: str) -> list:
    """Detect text placed at coordinates outside the visible page area."""
    findings = []
    try:
        with pdfplumber.open(filepath) as pdf:
            for page_num, page in enumerate(pdf.pages, 1):
                page_width = page.width
                page_height = page.height
                chars = page.chars

                offpage_chars = []
                for char in chars:
                    x = char.get("x0", 0)
                    y = char.get("top", 0)
                    # Check if character is outside visible page boundaries
                    if x < -10 or x > page_width + 10 or y < -10 or y > page_height + 10:
                        offpage_chars.append(char)

                if offpage_chars:
                    sample_text = "".join(c.get("text", "") for c in offpage_chars[:50])
                    findings.append(Finding(
                        technique="Off-Page Text",
                        severity="HIGH",
                        description=f"Found {len(offpage_chars)} characters placed outside visible page area",
                        evidence=f"Sample: '{sample_text[:80]}...'",
                        location=f"Page {page_num}",
                    ))

    except Exception as e:
        findings.append(Finding(
            technique="Scan Error",
            severity="INFO",
            description=f"Off-page detection error: {e}",
        ))
    return findings


# ============================================================
# Detection Module 5: Zero-Width / Invisible Unicode Detection
# ============================================================
def detect_invisible_unicode(filepath: str) -> list:
    """Detect zero-width characters and Unicode tags in text content."""
    findings = []
    try:
        reader = PdfReader(filepath)
        for page_num, page in enumerate(reader.pages, 1):
            text = page.extract_text() or ""

            # Check for known invisible characters
            found_invisible = {}
            for char in text:
                if char in INVISIBLE_CHARS:
                    name = INVISIBLE_CHARS[char]
                    found_invisible[name] = found_invisible.get(name, 0) + 1

                # Check for Unicode Tags block
                if ord(char) in TAG_RANGE:
                    tag_name = f"Unicode Tag U+{ord(char):05X}"
                    found_invisible[tag_name] = found_invisible.get(tag_name, 0) + 1

            if found_invisible:
                total = sum(found_invisible.values())
                detail = ", ".join(f"{name}: {count}" for name, count in found_invisible.items())
                severity = "CRITICAL" if total > 50 else "HIGH" if total > 10 else "MEDIUM"
                findings.append(Finding(
                    technique="Invisible Unicode Characters",
                    severity=severity,
                    description=f"Found {total} invisible/zero-width characters on page {page_num}",
                    evidence=detail,
                    location=f"Page {page_num}",
                ))

    except Exception as e:
        findings.append(Finding(
            technique="Scan Error",
            severity="INFO",
            description=f"Unicode detection error: {e}",
        ))
    return findings


# ============================================================
# Detection Module 6: Hidden Layer (OCG) Detection
# ============================================================
def detect_hidden_layers(filepath: str) -> list:
    """Detect Optional Content Groups (OCGs) with visibility set to OFF."""
    findings = []
    try:
        with pikepdf.open(filepath) as pdf:
            root = pdf.Root
            if "/OCProperties" in root:
                oc_props = root["/OCProperties"]
                findings.append(Finding(
                    technique="Optional Content Groups Present",
                    severity="MEDIUM",
                    description="PDF contains Optional Content Groups (layer system)",
                    location="Document Root /OCProperties",
                ))

                # Check for layers set to OFF
                if "/D" in oc_props:
                    default_config = oc_props["/D"]
                    if "/OFF" in default_config:
                        off_layers = default_config["/OFF"]
                        if len(off_layers) > 0:
                            layer_names = []
                            for layer_ref in off_layers:
                                try:
                                    layer = layer_ref
                                    if "/Name" in layer:
                                        layer_names.append(str(layer["/Name"]))
                                except Exception:
                                    layer_names.append("[unnamed]")

                            findings.append(Finding(
                                technique="Hidden OCG Layer",
                                severity="CRITICAL",
                                description=f"Found {len(off_layers)} layer(s) with visibility OFF (hidden content)",
                                evidence=f"Hidden layers: {', '.join(layer_names)}",
                                location="Document Root /OCProperties/D/OFF",
                            ))

                # Check all OCGs
                if "/OCGs" in oc_props:
                    total_layers = len(oc_props["/OCGs"])
                    if total_layers > 3:
                        findings.append(Finding(
                            technique="Suspicious Layer Count",
                            severity="LOW",
                            description=f"PDF contains {total_layers} content layers (unusual for a resume/document)",
                            location="Document Root /OCProperties/OCGs",
                        ))

    except Exception as e:
        findings.append(Finding(
            technique="Scan Error",
            severity="INFO",
            description=f"OCG detection error: {e}",
        ))
    return findings


# ============================================================
# Detection Module 7: Text Extraction Comparison
# ============================================================
def detect_text_discrepancy(filepath: str) -> list:
    """
    Compare text extracted by different methods. Large discrepancies
    may indicate hidden text that only some extractors capture.
    """
    findings = []
    try:
        # Method 1: pypdf extraction
        reader = PdfReader(filepath)
        pypdf_text = ""
        for page in reader.pages:
            pypdf_text += (page.extract_text() or "")

        # Method 2: pdfplumber extraction (respects layout)
        plumber_text = ""
        with pdfplumber.open(filepath) as pdf:
            for page in pdf.pages:
                plumber_text += (page.extract_text() or "")

        # Compare lengths - significant difference indicates hidden content
        len_diff = abs(len(pypdf_text) - len(plumber_text))
        max_len = max(len(pypdf_text), len(plumber_text), 1)
        discrepancy_pct = (len_diff / max_len) * 100

        if discrepancy_pct > 20:
            findings.append(Finding(
                technique="Text Extraction Discrepancy",
                severity="MEDIUM",
                description=(
                    f"Different extractors return significantly different text "
                    f"({discrepancy_pct:.1f}% difference: pypdf={len(pypdf_text)} chars, "
                    f"pdfplumber={len(plumber_text)} chars)"
                ),
                evidence="This may indicate hidden text visible to some parsers but not others",
                location="Full document",
            ))

        # Also check: does extracted text contain injection patterns?
        all_text = pypdf_text + " " + plumber_text
        text_findings = detect_injection_patterns(all_text, source="Extracted Text")
        findings.extend(text_findings)

    except Exception as e:
        findings.append(Finding(
            technique="Scan Error",
            severity="INFO",
            description=f"Text comparison error: {e}",
        ))
    return findings


# ============================================================
# Master Scanner
# ============================================================
def scan_pdf(filepath: str) -> ScanReport:
    """Run all detection modules on a PDF file and produce a report."""
    report = ScanReport(
        filepath=filepath,
        scan_time=datetime.now().isoformat(),
        file_size=os.path.getsize(filepath),
    )

    try:
        reader = PdfReader(filepath)
        report.page_count = len(reader.pages)
    except Exception:
        report.page_count = -1

    # Run all detection modules
    print(f"  [1/6] Scanning for invisible text (white/micro font)...")
    report.findings.extend(detect_invisible_text(filepath))

    print(f"  [2/6] Scanning metadata fields...")
    report.findings.extend(detect_metadata_injection(filepath))

    print(f"  [3/6] Scanning for off-page text...")
    report.findings.extend(detect_offpage_text(filepath))

    print(f"  [4/6] Scanning for invisible Unicode characters...")
    report.findings.extend(detect_invisible_unicode(filepath))

    print(f"  [5/6] Scanning for hidden layers (OCGs)...")
    report.findings.extend(detect_hidden_layers(filepath))

    print(f"  [6/6] Performing text extraction comparison...")
    report.findings.extend(detect_text_discrepancy(filepath))

    # Calculate overall risk
    report.calculate_risk()
    return report


# ============================================================
# Report Formatting
# ============================================================
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # Red
    "HIGH": "\033[93m",      # Yellow
    "MEDIUM": "\033[33m",    # Orange
    "LOW": "\033[36m",       # Cyan
    "INFO": "\033[37m",      # Gray
}
RESET = "\033[0m"
BOLD = "\033[1m"

RISK_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[36m",
    "CLEAN": "\033[92m",
}


def print_report(report: ScanReport):
    """Pretty-print a scan report to the terminal."""
    risk_color = RISK_COLORS.get(report.risk_level, RESET)

    print(f"\n{'─' * 70}")
    print(f"{BOLD}SCAN REPORT: {os.path.basename(report.filepath)}{RESET}")
    print(f"{'─' * 70}")
    print(f"  File:       {report.filepath}")
    print(f"  Size:       {report.file_size:,} bytes")
    print(f"  Pages:      {report.page_count}")
    print(f"  Scan Time:  {report.scan_time}")
    print(f"  Findings:   {len(report.findings)}")
    print(f"  Risk Score: {risk_color}{BOLD}{report.risk_score}/100 ({report.risk_level}){RESET}")
    print(f"{'─' * 70}")

    if not report.findings:
        print(f"  {RISK_COLORS['CLEAN']}✓ No suspicious content detected.{RESET}")
    else:
        for i, f in enumerate(report.findings, 1):
            color = SEVERITY_COLORS.get(f.severity, RESET)
            print(f"\n  {color}[{f.severity}]{RESET} Finding #{i}: {BOLD}{f.technique}{RESET}")
            print(f"    Description: {f.description}")
            if f.evidence:
                print(f"    Evidence:    {f.evidence[:120]}")
            if f.location:
                print(f"    Location:    {f.location}")

    print(f"\n{'─' * 70}\n")


def export_json_report(report: ScanReport, output_path: str):
    """Export scan report as JSON file."""
    data = {
        "filepath": report.filepath,
        "scan_time": report.scan_time,
        "file_size": report.file_size,
        "page_count": report.page_count,
        "risk_score": report.risk_score,
        "risk_level": report.risk_level,
        "findings_count": len(report.findings),
        "findings": [asdict(f) for f in report.findings],
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[*] JSON report exported: {output_path}")


# ============================================================
# Main: Scan files
# ============================================================
def main():
    print("=" * 70)
    print("  PDF Prompt Injection Detection Scanner (Blue Team)")
    print("=" * 70)

    # Determine files to scan
    if len(sys.argv) > 1:
        targets = sys.argv[1:]
    else:
        # Default: scan all PDFs in test_samples/
        sample_dir = "test_samples"
        if os.path.isdir(sample_dir):
            targets = sorted([
                os.path.join(sample_dir, f)
                for f in os.listdir(sample_dir) if f.endswith(".pdf")
            ])
        else:
            print(f"\n[!] No files specified and '{sample_dir}/' not found.")
            print(f"    Usage: python {sys.argv[0]} <file1.pdf> [file2.pdf ...]")
            print(f"    Or run pdf_injection_generator.py first to create test samples.")
            sys.exit(1)

    if not targets:
        print("[!] No PDF files found to scan.")
        sys.exit(1)

    print(f"\n[*] Scanning {len(targets)} file(s)...\n")

    all_reports = []
    for filepath in targets:
        if not os.path.isfile(filepath):
            print(f"[!] File not found: {filepath}")
            continue
        print(f"[*] Scanning: {filepath}")
        report = scan_pdf(filepath)
        all_reports.append(report)
        print_report(report)

    # Summary table
    print(f"\n{'=' * 70}")
    print(f"  SUMMARY")
    print(f"{'=' * 70}")
    print(f"  {'File':<42s} {'Findings':>8s}  {'Score':>5s}  {'Risk':>10s}")
    print(f"  {'─' * 42} {'─' * 8}  {'─' * 5}  {'─' * 10}")
    for r in all_reports:
        risk_color = RISK_COLORS.get(r.risk_level, RESET)
        name = os.path.basename(r.filepath)
        print(f"  {name:<42s} {len(r.findings):>8d}  {r.risk_score:>5d}  {risk_color}{r.risk_level:>10s}{RESET}")
    print(f"{'=' * 70}\n")

    # Export JSON reports
    os.makedirs("scan_reports", exist_ok=True)
    for r in all_reports:
        json_name = os.path.splitext(os.path.basename(r.filepath))[0] + "_report.json"
        export_json_report(r, os.path.join("scan_reports", json_name))

    print(f"\n[✓] All scans complete. JSON reports saved in scan_reports/")


if __name__ == "__main__":
    main()
