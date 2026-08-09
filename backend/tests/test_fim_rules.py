import pytest
from app.detection.rules.fim_rules import (
    FIMExecutableInDownloadsRule, FIMDoubleExtensionRule,
    FIMStartupModificationRule, FIMMassFileModificationRule
)
from app.models.threat import ThreatSeverity, ThreatType


def test_backend_fim_executable_in_downloads():
    rule = FIMExecutableInDownloadsRule()
    res = rule.evaluate(
        file_name="setup.exe",
        full_path="/home/rebel/Downloads/setup.exe",
        extension=".exe",
        file_size=1024,
        sha256="abc",
        is_executable=True,
        event_type="CREATED"
    )
    assert res is not None
    assert res.severity == ThreatSeverity.HIGH
    assert res.threat_type == ThreatType.FIM_EXECUTABLE_IN_DOWNLOADS


def test_backend_fim_double_extension():
    rule = FIMDoubleExtensionRule()
    res = rule.evaluate(
        file_name="invoice.docx.exe",
        full_path="/home/rebel/Documents/invoice.docx.exe",
        extension=".exe",
        file_size=2048,
        sha256="xyz",
        is_executable=True
    )
    assert res is not None
    assert res.severity == ThreatSeverity.CRITICAL
    assert res.threat_type == ThreatType.FIM_DOUBLE_EXTENSION_MASQUERADE


def test_backend_fim_startup_modification():
    rule = FIMStartupModificationRule()
    res = rule.evaluate(
        file_name="persist.sh",
        full_path="/etc/init.d/persist.sh",
        extension=".sh",
        file_size=512,
        sha256="123",
        is_executable=True,
        event_type="CREATED"
    )
    assert res is not None
    assert res.severity == ThreatSeverity.HIGH
    assert res.threat_type == ThreatType.FIM_STARTUP_MODIFICATION


def test_backend_fim_mass_modification():
    rule = FIMMassFileModificationRule()
    res = rule.evaluate(
        file_name="test.doc",
        full_path="/home/rebel/Documents/test.doc",
        extension=".doc",
        file_size=100,
        sha256="def",
        modification_count=15
    )
    assert res is not None
    assert res.severity == ThreatSeverity.CRITICAL
    assert res.threat_type == ThreatType.FIM_MASS_FILE_MODIFICATION
