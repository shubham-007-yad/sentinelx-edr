import pytest
from app.models.threat import ThreatSeverity, ThreatType
from app.detection.scoring import ThreatScorer, threat_scorer
from app.detection import (
    DetectionEngine,
    DangerousExtensionRule,
    DoubleExtensionRule,
    AutoRunRule,
    KnownMalwareRule,
    HiddenExecutableRule,
    AnomalousFileRule,
    RuleResult,
)


def test_standardized_severity_levels():
    """Validates presence and numeric score values for LOW, MEDIUM, HIGH, CRITICAL."""
    assert threat_scorer.get_severity_score(ThreatSeverity.LOW) == 25
    assert threat_scorer.get_severity_score(ThreatSeverity.MEDIUM) == 50
    assert threat_scorer.get_severity_score(ThreatSeverity.HIGH) == 75
    assert threat_scorer.get_severity_score(ThreatSeverity.CRITICAL) == 100

    # String input support
    assert threat_scorer.get_severity_score("CRITICAL") == 100
    assert threat_scorer.get_severity_score("HIGH") == 75
    assert threat_scorer.get_severity_score("MEDIUM") == 50
    assert threat_scorer.get_severity_score("LOW") == 25


def test_spec_required_severity_mappings():
    """
    Validates example mappings specified in Phase 6 requirements:
    .exe -> HIGH
    .dll -> HIGH
    .bat -> HIGH
    .ps1 -> HIGH
    Double extension -> CRITICAL
    autorun.inf -> CRITICAL
    """
    # File Extension Mappings
    assert threat_scorer.get_extension_severity(".exe") == ThreatSeverity.HIGH
    assert threat_scorer.get_extension_severity(".dll") == ThreatSeverity.HIGH
    assert threat_scorer.get_extension_severity(".bat") == ThreatSeverity.HIGH
    assert threat_scorer.get_extension_severity(".ps1") == ThreatSeverity.HIGH

    # Rule Mappings
    assert threat_scorer.get_rule_severity("Double Extension Detection") == ThreatSeverity.CRITICAL
    assert threat_scorer.get_rule_severity("Autorun Detection") == ThreatSeverity.CRITICAL


def test_detection_rules_evaluate_with_centralized_scores():
    """Verifies that evaluation results from rules include standardized severities and scores."""
    danger_rule = DangerousExtensionRule()
    double_rule = DoubleExtensionRule()
    autorun_rule = AutoRunRule()

    # .exe check
    res_exe = danger_rule.evaluate(
        file_name="payload.exe",
        full_path="E:\\payload.exe",
        extension=".exe",
        file_size=1024,
        sha256="abc"
    )
    assert res_exe is not None
    assert res_exe.severity == ThreatSeverity.HIGH
    assert res_exe.score == 75

    # .dll check
    res_dll = danger_rule.evaluate(
        file_name="inject.dll",
        full_path="E:\\inject.dll",
        extension=".dll",
        file_size=1024,
        sha256="abc"
    )
    assert res_dll is not None
    assert res_dll.severity == ThreatSeverity.HIGH
    assert res_dll.score == 75

    # .bat check
    res_bat = danger_rule.evaluate(
        file_name="script.bat",
        full_path="E:\\script.bat",
        extension=".bat",
        file_size=1024,
        sha256="abc"
    )
    assert res_bat is not None
    assert res_bat.severity == ThreatSeverity.HIGH
    assert res_bat.score == 75

    # .ps1 check
    res_ps1 = danger_rule.evaluate(
        file_name="setup.ps1",
        full_path="E:\\setup.ps1",
        extension=".ps1",
        file_size=1024,
        sha256="abc"
    )
    assert res_ps1 is not None
    assert res_ps1.severity == ThreatSeverity.HIGH
    assert res_ps1.score == 75

    # Double extension check -> CRITICAL
    res_double = double_rule.evaluate(
        file_name="doc.pdf.exe",
        full_path="E:\\doc.pdf.exe",
        extension=".exe",
        file_size=1024,
        sha256="abc"
    )
    assert res_double is not None
    assert res_double.severity == ThreatSeverity.CRITICAL
    assert res_double.score == 100

    # autorun.inf check -> CRITICAL
    res_autorun = autorun_rule.evaluate(
        file_name="autorun.inf",
        full_path="E:\\autorun.inf",
        extension=".inf",
        file_size=100,
        sha256="abc"
    )
    assert res_autorun is not None
    assert res_autorun.severity == ThreatSeverity.CRITICAL
    assert res_autorun.score == 100


def test_dynamic_scoring_adjustments():
    """Verifies that centralized scoring can be dynamically adjusted without altering rule code."""
    scorer = ThreatScorer()

    # Change .ps1 to CRITICAL dynamically
    scorer.set_extension_severity(".ps1", ThreatSeverity.CRITICAL)
    assert scorer.get_extension_severity(".ps1") == ThreatSeverity.CRITICAL

    # Change CRITICAL score weight from 100 to 150
    scorer.set_severity_weight(ThreatSeverity.CRITICAL, 150)
    assert scorer.get_severity_score(ThreatSeverity.CRITICAL) == 150

    # Reset to defaults
    scorer.reset_to_defaults()
    assert scorer.get_extension_severity(".ps1") == ThreatSeverity.HIGH
    assert scorer.get_severity_score(ThreatSeverity.CRITICAL) == 100


def test_composite_score_calculation():
    """Verifies aggregate composite score computation across multiple rule findings."""
    res1 = RuleResult(
        rule_name="Dangerous Extension Detection",
        threat_type=ThreatType.SUSPICIOUS_EXTENSION,
        severity=ThreatSeverity.HIGH,
        description=".exe detected"
    )
    res2 = RuleResult(
        rule_name="Autorun Detection",
        threat_type=ThreatType.AUTORUN_SCRIPT,
        severity=ThreatSeverity.CRITICAL,
        description="autorun.inf detected"
    )

    summary = threat_scorer.calculate_composite_score([res1, res2])
    assert summary["overall_severity"] == ThreatSeverity.CRITICAL
    assert summary["total_threat_points"] == 175  # 75 + 100
    assert summary["composite_score"] == 100  # capped at 100
    assert summary["findings_count"] == 2
