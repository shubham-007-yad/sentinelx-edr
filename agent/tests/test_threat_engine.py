import pytest
try:
    from agent.threat_engine import AgentThreatEngine
except ModuleNotFoundError:
    from threat_engine import AgentThreatEngine


def test_agent_threat_engine_analysis():
    engine = AgentThreatEngine()

    # Test EICAR malware hash
    findings1 = engine.analyze_file(
        file_name="eicar_test.com",
        full_path="E:\\eicar_test.com",
        extension=".com",
        file_size=68,
        sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    )
    assert any(f.threat_type == "KNOWN_MALWARE" for f in findings1)

    # Test Dual extension
    findings2 = engine.analyze_file(
        file_name="payroll_2026.xlsx.vbs",
        full_path="E:\\payroll_2026.xlsx.vbs",
        extension=".vbs",
        file_size=4096,
        sha256="9999999999999999999999999999999999999999999999999999999999999999"
    )
    assert any(f.threat_type == "DOUBLE_EXTENSION" for f in findings2)
