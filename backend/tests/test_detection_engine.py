import pytest
from app.detection import (
    DetectionEngine,
    BaseRule,
    RuleResult,
    DangerousExtensionRule,
    HiddenExecutableRule,
    AutoRunRule,
    DoubleExtensionRule,
    KnownMalwareRule,
    AnomalousFileRule
)
from app.models.threat import ThreatSeverity, ThreatType


def test_dangerous_extension_rule():
    rule = DangerousExtensionRule()
    res = rule.evaluate(
        file_name="installer.exe",
        full_path="E:\\installer.exe",
        extension=".exe",
        file_size=1024,
        sha256="abc123sha256"
    )
    assert res is not None
    assert res.rule_name == "Dangerous Extension Detection"
    assert res.threat_type == ThreatType.SUSPICIOUS_EXTENSION
    assert res.severity == ThreatSeverity.HIGH
    assert ".exe" in res.description


def test_phase3_dangerous_extensions_batch():
    rule = DangerousExtensionRule()
    phase3_extensions = [".exe", ".dll", ".scr", ".bat", ".cmd", ".com", ".ps1", ".vbs", ".js"]
    for ext in phase3_extensions:
        res = rule.evaluate(
            file_name=f"test_payload{ext}",
            full_path=f"E:\\test_payload{ext}",
            extension=ext,
            file_size=2048,
            sha256="1234567890abcdef"
        )
        assert res is not None, f"Failed to flag dangerous extension {ext}"
        assert res.severity == ThreatSeverity.HIGH
        assert res.rule_name == "Dangerous Extension Detection"


def test_hidden_executable_rule():
    rule = HiddenExecutableRule()
    res = rule.evaluate(
        file_name=".stealth_payload.exe",
        full_path="E:\\.stealth_payload.exe",
        extension=".exe",
        file_size=2048,
        sha256="xyz789sha256",
        is_hidden=True
    )
    assert res is not None
    assert res.threat_type == ThreatType.HIDDEN_EXECUTABLE
    assert res.severity == ThreatSeverity.HIGH


def test_autorun_rule():
    rule = AutoRunRule()
    res = rule.evaluate(
        file_name="autorun.inf",
        full_path="E:\\autorun.inf",
        extension=".inf",
        file_size=50,
        sha256="autorunsha256"
    )
    assert res is not None
    assert res.threat_type == ThreatType.AUTORUN_SCRIPT
    assert res.severity == ThreatSeverity.HIGH


def test_double_extension_rule():
    rule = DoubleExtensionRule()
    res = rule.evaluate(
        file_name="financial_report.pdf.exe",
        full_path="E:\\financial_report.pdf.exe",
        extension=".exe",
        file_size=500000,
        sha256="doubleextsha256"
    )
    assert res is not None
    assert res.threat_type == ThreatType.DOUBLE_EXTENSION
    assert res.severity == ThreatSeverity.CRITICAL


def test_known_malware_rule():
    rule = KnownMalwareRule()
    res = rule.evaluate(
        file_name="test.com",
        full_path="E:\\test.com",
        extension=".com",
        file_size=68,
        sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"  # EICAR
    )
    assert res is not None
    assert res.threat_type == ThreatType.KNOWN_MALWARE
    assert res.severity == ThreatSeverity.CRITICAL


def test_anomalous_file_rule():
    rule = AnomalousFileRule()
    res = rule.evaluate(
        file_name="svchost.exe",
        full_path="E:\\svchost.exe",
        extension=".exe",
        file_size=10000,
        sha256="svchostsha256"
    )
    assert res is not None
    assert res.threat_type == ThreatType.ANOMALOUS_FILE
    assert res.severity == ThreatSeverity.HIGH


def test_detection_engine_aggregation_and_registration():
    engine = DetectionEngine()

    # Custom rule class
    class CustomZeroByteRule(BaseRule):
        rule_name = "Zero Byte Binary Exception"
        threat_type = ThreatType.ANOMALOUS_FILE
        severity = ThreatSeverity.LOW

        def evaluate(self, file_name, full_path, extension, file_size, sha256, is_hidden=False):
            if file_size == 0 and extension == ".exe":
                return RuleResult(
                    rule_name=self.rule_name,
                    threat_type=self.threat_type,
                    severity=self.severity,
                    description="Zero byte executable detected."
                )
            return None

    engine.register_rule(CustomZeroByteRule())

    # Evaluate zero byte executable
    findings = engine.evaluate_file(
        file_name="zero.exe",
        full_path="E:\\zero.exe",
        extension=".exe",
        file_size=0,
        sha256="0000"
    )

    assert any(f.rule_name == "Zero Byte Binary Exception" for f in findings)
