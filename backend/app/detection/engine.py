from typing import List, Optional, Union, Dict, Any
from app.detection.rules.base import BaseRule, RuleResult
from app.detection.rules.process_base import BaseProcessRule, ProcessRuleResult
from app.detection.rules.dangerous_extensions import DangerousExtensionRule, HiddenExecutableRule
from app.detection.rules.autorun import AutoRunRule
from app.detection.rules.double_extension import DoubleExtensionRule
from app.detection.rules.known_malware import KnownMalwareRule
from app.detection.rules.anomalous_file import AnomalousFileRule
from app.detection.rules.suspicious_powershell import SuspiciousPowerShellRule
from app.detection.rules.suspicious_cmd import SuspiciousCmdRule
from app.detection.rules.lolbins import LOLBinsRule
from app.detection.rules.parent_child_chain import ParentChildChainRule
from app.detection.rules.event_log_rules import (
    BaseEventRule,
    EventRuleResult,
    BruteForceLogonRule,
    NewAdminAccountRule,
    AccountDisabledRule,
    SuspiciousLoginTimeRule,
    SimultaneousMultiDeviceLoginRule,
    RemoteLogonRule,
    NewServiceCreationRule,
    ScheduledTaskCreationRule,
    RegistryRunKeyModificationRule,
    StartupFolderModificationRule,
    DefenseEvasionLogClearingRule
)


class DetectionEngine:
    """
    Modular Detection Rule Engine for SentinelX EDR.
    Evaluates file metadata records, live process telemetry, and OS event logs against registered rule plugins.
    """

    def __init__(
        self,
        rules: Optional[List[BaseRule]] = None,
        process_rules: Optional[List[BaseProcessRule]] = None,
        event_rules: Optional[List[BaseEventRule]] = None
    ):
        if rules is None:
            self.rules: List[BaseRule] = [
                KnownMalwareRule(),
                DoubleExtensionRule(),
                HiddenExecutableRule(),
                AutoRunRule(),
                DangerousExtensionRule(),
                AnomalousFileRule(),
            ]
        else:
            self.rules = list(rules)

        if process_rules is None:
            self.process_rules: List[BaseProcessRule] = [
                SuspiciousPowerShellRule(),
                SuspiciousCmdRule(),
                LOLBinsRule(),
                ParentChildChainRule(),
            ]
        else:
            self.process_rules = list(process_rules)

        if event_rules is None:
            self.event_rules: List[BaseEventRule] = [
                BruteForceLogonRule(),
                NewAdminAccountRule(),
                AccountDisabledRule(),
                SuspiciousLoginTimeRule(),
                SimultaneousMultiDeviceLoginRule(),
                RemoteLogonRule(),
                NewServiceCreationRule(),
                ScheduledTaskCreationRule(),
                RegistryRunKeyModificationRule(),
                StartupFolderModificationRule(),
                DefenseEvasionLogClearingRule(),
            ]
        else:
            self.event_rules = list(event_rules)




    def register_rule(self, rule: Union[BaseRule, BaseProcessRule]) -> None:
        """Dynamically registers a new file or process detection rule at runtime."""
        if isinstance(rule, BaseProcessRule):
            self.process_rules.append(rule)
        else:
            self.rules.append(rule)

    def evaluate_file(
        self,
        file_name: str,
        full_path: str,
        extension: Optional[str],
        file_size: int,
        sha256: str,
        is_hidden: bool = False
    ) -> List[RuleResult]:
        """
        Evaluates a file against all registered file rules in the detection engine.
        Returns a list of RuleResult objects for all matching rules.
        """
        findings: List[RuleResult] = []
        for rule in self.rules:
            result = rule.evaluate(
                file_name=file_name,
                full_path=full_path,
                extension=extension,
                file_size=file_size,
                sha256=sha256,
                is_hidden=is_hidden
            )
            if result is not None:
                findings.append(result)
        return findings

    def evaluate_process(
        self,
        pid: int,
        name: str,
        cmdline: Optional[str] = None,
        exe_path: Optional[str] = None,
        username: Optional[str] = None,
        ppid: Optional[int] = None,
        parent_name: Optional[str] = None
    ) -> List[ProcessRuleResult]:
        """
        Evaluates a running process against all registered process behavioral rules.
        Returns a list of ProcessRuleResult objects for all matching rules.
        """
        findings: List[ProcessRuleResult] = []
        for rule in self.process_rules:
            if isinstance(rule, ParentChildChainRule):
                result = rule.evaluate_process_chain(
                    pid=pid,
                    name=name,
                    ppid=ppid,
                    parent_name=parent_name,
                    cmdline=cmdline,
                    exe_path=exe_path,
                    username=username
                )
            else:
                result = rule.evaluate_process(
                    pid=pid,
                    name=name,
                    cmdline=cmdline,
                    exe_path=exe_path,
                    username=username,
                    ppid=ppid
                )

            if result is not None:
                findings.append(result)
        return findings

    def evaluate_event_log(self, event: Dict[str, Any]) -> List[EventRuleResult]:
        """
        Evaluates a single OS Security Event against registered event rules.
        """
        findings: List[EventRuleResult] = []
        for rule in self.event_rules:
            result = rule.evaluate(event)
            if result is not None:
                findings.append(result)
        return findings

    def evaluate_event_log_batch(self, events: List[Dict[str, Any]]) -> List[EventRuleResult]:
        """
        Evaluates a sequence of OS Security Events against registered event rules (including batch pattern rules).
        """
        findings: List[EventRuleResult] = []
        for rule in self.event_rules:
            if hasattr(rule, "evaluate_batch"):
                batch_results = rule.evaluate_batch(events)
                findings.extend(batch_results)
            else:
                for event in events:
                    result = rule.evaluate(event)
                    if result is not None:
                        findings.append(result)
        return findings



