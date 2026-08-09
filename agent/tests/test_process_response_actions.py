import pytest
from command_executor import CommandExecutor


def test_command_executor_process_actions():
    executor = CommandExecutor()

    # 1. MARK_TRUSTED
    res_trust = executor.execute("MARK_TRUSTED", {"process_name": "notepad.exe", "pid": 1234})
    assert res_trust.success is True
    assert "notepad.exe" in res_trust.message

    # 2. ADD_ALLOWLIST
    res_allow = executor.execute("ADD_ALLOWLIST", {"process_name": "custom_agent.exe", "exe_path": "/usr/bin/custom_agent"})
    assert res_allow.success is True
    assert "custom_agent.exe" in res_allow.message

    # 3. TERMINATE_PROCESS (non-existent PID fallback handle)
    res_term = executor.execute("TERMINATE_PROCESS", {"pid": 999999})
    assert res_term.success is True
    assert "0 process(es)" in res_term.message

    # 4. SUSPEND_PROCESS (non-existent PID fallback handle)
    res_susp = executor.execute("SUSPEND_PROCESS", {"pid": 999999})
    assert res_susp.success is True
    assert "0 process(es)" in res_susp.message
