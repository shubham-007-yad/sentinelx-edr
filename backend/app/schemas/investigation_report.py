from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict, Field


class MitreTechnique(BaseModel):
    tactic: str           # e.g., "Initial Access", "Execution", "Command and Control", "Impact"
    technique_id: str     # e.g., "T1091", "T1059.001", "T1071.001", "T1486"
    technique_name: str   # e.g., "Replication Through Removable Media"
    description: str


class InvestigationReportData(BaseModel):
    report_id: str
    case_id: Optional[str] = None
    correlation_id: Optional[str] = None
    generated_at: datetime
    generated_by: str = "SentinelX AI Analyst"
    executive_summary: Dict[str, Any] = Field(default_factory=dict)
    technical_report: Dict[str, Any] = Field(default_factory=dict)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_list: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_attack_mapping: List[MitreTechnique] = Field(default_factory=list)
    response_actions: List[Dict[str, Any]] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)
