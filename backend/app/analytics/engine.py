"""
Analytics Engine Main Orchestrator
Provides unified access to business metrics, telemetry aggregation, trends, MITRE mapping, and reporting.
"""

from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session

from app.analytics.aggregation import TelemetryAggregator
from app.analytics.metrics import BusinessMetricsCalculator
from app.analytics.trends import TrendAnalyzer
from app.analytics.mitre import MitreMapper
from app.analytics.reporting import ExecutiveReporter


class AnalyticsEngine:
    def __init__(self, db: Session):
        self.db = db
        self.aggregator = TelemetryAggregator(db)
        self.metrics = BusinessMetricsCalculator(db)
        self.trends = TrendAnalyzer(db)
        self.mitre = MitreMapper(db)
        self.reporter = ExecutiveReporter(db)

    def get_top_metrics(self) -> Dict[str, Any]:
        """Returns the top executive KPI cards."""
        return self.metrics.calculate_top_executive_metrics()

    def get_executive_dashboard_summary(self, timeframe_days: int = 7) -> Dict[str, Any]:
        """Returns the high-level decision support summary for CISO & Executive Dashboards."""
        top_metrics = self.get_top_metrics()
        posture = self.metrics.calculate_security_posture_overview(timeframe_days)
        severity_dist = self.aggregator.aggregate_alerts_by_severity()
        status_dist = self.aggregator.aggregate_alerts_by_status()
        velocity = self.trends.get_trend_velocity(timeframe_days)
        response_sla = self.metrics.calculate_response_time_metrics(timeframe_days)
        top_mitre = self.mitre.analyze_mitre_attack_coverage(timeframe_days, limit_techniques=5)
        top_risk_endpoints = self.metrics.calculate_endpoint_risk_scores(timeframe_days)[:5]

        return {
            "top_metrics": top_metrics,
            "posture": posture,
            "alerts_by_severity": severity_dist,
            "alerts_by_status": status_dist,
            "incident_velocity": velocity,
            "sla_performance": response_sla,
            "top_risk_endpoints": top_risk_endpoints,
            "mitre_summary": top_mitre,
        }

    def get_endpoint_risk_analytics(self, timeframe_days: int = 30, limit: int = 10) -> List[Dict[str, Any]]:
        """Returns ordered list of endpoints with risk scores and threat counts."""
        scores = self.metrics.calculate_endpoint_risk_scores(timeframe_days)
        return scores[:limit]

    def get_mitre_attack_analytics(self, timeframe_days: int = 30, limit_techniques: int = 10) -> Dict[str, Any]:
        """Returns MITRE ATT&CK tactics breakdown and top techniques observed."""
        return self.mitre.analyze_mitre_attack_coverage(timeframe_days, limit_techniques=limit_techniques)

    def get_mitre_matrix_heatmap(self, timeframe_days: int = 30) -> Dict[str, Any]:
        """Returns full MITRE ATT&CK Matrix Heatmap, tactic columns, technique frequency, and coverage %."""
        return self.mitre.get_mitre_matrix_heatmap(timeframe_days=timeframe_days)

    def get_incident_trends(self, days: int = 30) -> Dict[str, Any]:
        """Returns daily trend lines and velocity indicators."""
        daily = self.trends.get_daily_incident_trends(days=days)
        velocity = self.trends.get_trend_velocity(period_days=7)
        return {
            "daily_trends": daily,
            "velocity": velocity
        }

    def get_multi_stream_trends(
        self,
        timeframe: str = "7d",
        start_date: Optional[Any] = None,
        end_date: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Returns multi-stream trend chart data for Threats, Alerts, Endpoint, USB, Network, and Process events."""
        return self.trends.get_multi_stream_trends(
            timeframe=timeframe,
            start_date=start_date,
            end_date=end_date
        )

    def get_response_performance(self, timeframe_days: int = 30) -> Dict[str, Any]:
        """Returns MTTA, MTTR, and SLA compliance metrics."""
        return self.metrics.calculate_response_time_metrics(timeframe_days)

    def export_analytics_csv(self, dataset_type: str, timeframe_days: int = 30) -> str:
        """Exports analytics dataset (incidents, endpoints, mitre) as CSV."""
        return self.reporter.export_dataset_to_csv(dataset_type, timeframe_days)

    def generate_executive_report(self, timeframe_days: int = 7) -> Dict[str, Any]:
        """Generates a complete executive report package."""
        return self.reporter.generate_executive_summary_report(timeframe_days)

    def generate_technical_report(self, timeframe_days: int = 30) -> Dict[str, Any]:
        """Generates a detailed technical report package (incidents, timeline, IOCs, response logs)."""
        return self.reporter.generate_technical_report(timeframe_days)

    def export_report_pdf(self, report_type: str = "executive", timeframe_days: int = 30) -> bytes:
        """Generates a multi-page PDF document for Executive or Technical report."""
        return self.reporter.export_report_pdf(report_type=report_type, timeframe_days=timeframe_days)
