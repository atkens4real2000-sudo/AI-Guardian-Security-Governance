"""
Governance Mapping Module for AI Guardian Toolkit.

Maps red team assessment findings to compliance framework controls across:
- NIST AI Risk Management Framework (AI RMF 1.0)
- EU AI Act Risk Tiers
- ISO/IEC 42001 AI Management System Controls
- OWASP Top 10 for LLM Applications 2025

This module receives assessment data as dicts/dataclass instances from the
assessment_engine and produces unified cross-framework compliance mappings.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional

from ai_frameworks import (
    NIST_AI_RMF,
    EU_AI_ACT_RISK_TIERS,
    ISO_42001_CONTROLS,
    OWASP_LLM_TOP_10,
    get_all_nist_subcategories,
)


# ---------------------------------------------------------------------------
# OWASP → NIST AI RMF MAPPING
# Maps each OWASP LLM category to relevant NIST AI RMF subcategories.
# ---------------------------------------------------------------------------

OWASP_TO_NIST_MAPPING: Dict[str, List[str]] = {
    "LLM01": ["GOVERN-1.1", "GOVERN-1.2", "MEASURE-2.5", "MANAGE-2.3", "MAP-2.2"],
    "LLM02": ["GOVERN-1.1", "GOVERN-4.1", "MEASURE-2.2", "MANAGE-1.3", "MAP-4.1"],
    "LLM03": ["GOVERN-3.2", "GOVERN-6.1", "MEASURE-3.1", "MANAGE-3.1"],
    "LLM04": ["MAP-2.1", "MEASURE-2.2", "MEASURE-2.5", "MANAGE-2.1"],
    "LLM05": ["GOVERN-1.2", "MEASURE-2.1", "MEASURE-2.4", "MANAGE-2.3"],
    "LLM06": ["GOVERN-1.3", "GOVERN-2.1", "MEASURE-2.4", "MANAGE-1.2", "MANAGE-2.4"],
    "LLM07": ["GOVERN-1.1", "GOVERN-4.1", "MEASURE-2.5", "MANAGE-1.3"],
    "LLM08": ["MAP-2.1", "MEASURE-2.2", "MEASURE-2.5", "MANAGE-2.1"],
    "LLM09": ["MAP-1.1", "MAP-2.2", "MEASURE-2.1", "MEASURE-2.3", "MANAGE-1.1"],
    "LLM10": ["GOVERN-6.2", "MEASURE-2.4", "MANAGE-2.2", "MANAGE-2.3"],
}


# ---------------------------------------------------------------------------
# OWASP → ISO 42001 MAPPING
# Maps each OWASP LLM category to relevant ISO 42001 control objectives.
# ---------------------------------------------------------------------------

OWASP_TO_ISO_MAPPING: Dict[str, List[str]] = {
    "LLM01": ["A.6.3", "A.9.3", "A.9.4"],      # V&V, monitoring, human oversight
    "LLM02": ["A.7.2", "A.8.2", "A.5.2"],       # Data mgmt, transparency, impact
    "LLM03": ["A.10.2", "A.4.3", "A.6.2"],      # Suppliers, tools, development
    "LLM04": ["A.7.2", "A.7.3", "A.7.4"],       # Data mgmt, quality, provenance
    "LLM05": ["A.6.3", "A.6.4", "A.9.2"],       # V&V, deployment, intended use
    "LLM06": ["A.9.4", "A.9.2", "A.5.2"],       # Human oversight, intended use, impact
    "LLM07": ["A.8.2", "A.6.6", "A.9.3"],       # Transparency, documentation, monitoring
    "LLM08": ["A.7.2", "A.7.3", "A.4.4"],       # Data mgmt, quality, computing resources
    "LLM09": ["A.8.2", "A.8.3", "A.6.3"],       # Transparency, info provision, V&V
    "LLM10": ["A.4.4", "A.6.4", "A.9.3"],       # Computing resources, deployment, monitoring
}


# ---------------------------------------------------------------------------
# EU AI ACT OBLIGATION MAPPING
# Maps OWASP categories to EU AI Act requirement indices (for HIGH tier).
# Indices correspond to the requirements list in EU_AI_ACT_RISK_TIERS["HIGH"].
# ---------------------------------------------------------------------------

OWASP_TO_EU_HIGH_MAPPING: Dict[str, List[int]] = {
    "LLM01": [0, 5, 6],      # Risk assessment, human oversight, robustness
    "LLM02": [1, 3, 4],      # Data quality, documentation, deployer info
    "LLM03": [8, 9],         # Conformity assessment, quality management
    "LLM04": [1, 6],         # Data quality, robustness
    "LLM05": [0, 6],         # Risk assessment, robustness
    "LLM06": [5, 0, 9],      # Human oversight, risk assessment, quality mgmt
    "LLM07": [3, 4, 2],      # Documentation, deployer info, traceability
    "LLM08": [1, 6, 9],      # Data quality, robustness, quality management
    "LLM09": [0, 3, 6],      # Risk assessment, documentation, robustness
    "LLM10": [0, 6, 9],      # Risk assessment, robustness, quality management
}


# ---------------------------------------------------------------------------
# DATACLASSES
# ---------------------------------------------------------------------------

@dataclass
class FrameworkGap:
    """Represents a single compliance gap within a governance framework."""
    framework: str          # "NIST AI RMF" / "EU AI Act" / "ISO 42001" / "OWASP"
    control_id: str         # e.g., "GOVERN-1.1", "A.6.3", "LLM01"
    control_name: str
    gap_description: str    # What specifically failed
    severity: str           # HIGH / MEDIUM / LOW
    triggered_by: List[str] = field(default_factory=list)  # OWASP categories
    remediation: str = ""   # Recommended fix
    status: str = "OPEN"    # OPEN / REMEDIATED

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary."""
        return asdict(self)


@dataclass
class FrameworkMapping:
    """Assessment results mapped to a single governance framework."""
    framework: str
    total_controls: int
    assessed_controls: int
    gaps_found: int
    compliance_percentage: float
    gaps: List[FrameworkGap] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "framework": self.framework,
            "total_controls": self.total_controls,
            "assessed_controls": self.assessed_controls,
            "gaps_found": self.gaps_found,
            "compliance_percentage": round(self.compliance_percentage, 2),
            "gaps": [g.to_dict() for g in self.gaps],
        }


@dataclass
class UnifiedMapping:
    """Cross-framework compliance mapping produced by a governance assessment."""
    assessment_date: str
    target_system: str
    risk_tier: str           # EU AI Act tier
    nist_mapping: FrameworkMapping = None
    eu_mapping: FrameworkMapping = None
    iso_mapping: FrameworkMapping = None
    owasp_mapping: FrameworkMapping = None
    overall_compliance: float = 0.0   # Average across frameworks
    priority_gaps: List[FrameworkGap] = field(default_factory=list)

    @property
    def framework_mappings(self) -> Dict[str, "FrameworkMapping"]:
        """Return a dict of all framework mappings for iteration."""
        mappings = {}
        if self.nist_mapping is not None:
            mappings["NIST AI RMF"] = self.nist_mapping
        if self.eu_mapping is not None:
            mappings["EU AI Act"] = self.eu_mapping
        if self.iso_mapping is not None:
            mappings["ISO 42001"] = self.iso_mapping
        if self.owasp_mapping is not None:
            mappings["OWASP LLM Top 10"] = self.owasp_mapping
        return mappings

    def to_dict(self) -> Dict:
        """Serialize the entire unified mapping to a dict for JSON export."""
        return {
            "assessment_date": self.assessment_date,
            "target_system": self.target_system,
            "risk_tier": self.risk_tier,
            "nist_mapping": self.nist_mapping.to_dict() if self.nist_mapping else None,
            "eu_mapping": self.eu_mapping.to_dict() if self.eu_mapping else None,
            "iso_mapping": self.iso_mapping.to_dict() if self.iso_mapping else None,
            "owasp_mapping": self.owasp_mapping.to_dict() if self.owasp_mapping else None,
            "overall_compliance": round(self.overall_compliance, 2),
            "priority_gaps": [g.to_dict() for g in self.priority_gaps],
        }


# ---------------------------------------------------------------------------
# HELPER UTILITIES
# ---------------------------------------------------------------------------

def _lookup_nist_subcategory(sub_id: str, subcats: List[Dict]) -> Optional[Dict]:
    """Find a NIST subcategory dict by its ID from the flat list."""
    for sc in subcats:
        if sc["subcategory_id"] == sub_id:
            return sc
    return None


def _lookup_iso_objective(objective_id: str) -> Optional[Dict]:
    """Resolve an ISO 42001 objective like 'A.6.3' from the controls dict.

    The ISO_42001_CONTROLS dict is keyed by topic (e.g., 'A.6') and each topic
    has an 'objectives' dict keyed by objective ID (e.g., 'A.6.3').
    """
    parts = objective_id.rsplit(".", 1)
    if len(parts) != 2:
        return None
    topic_id = parts[0]  # e.g., "A.6"
    topic = ISO_42001_CONTROLS.get(topic_id)
    if topic is None:
        return None
    return topic.get("objectives", {}).get(objective_id)


def _severity_rank(severity: str) -> int:
    """Return a numeric rank for sorting (higher = more severe)."""
    return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(severity.upper(), 0)


# ---------------------------------------------------------------------------
# GovernanceMapper
# ---------------------------------------------------------------------------

class GovernanceMapper:
    """Maps red team assessment findings to multi-framework compliance gaps.

    Accepts vulnerability data (lists of triggered OWASP categories and per-
    category test results) and produces FrameworkMapping and UnifiedMapping
    objects that quantify compliance posture across NIST AI RMF, EU AI Act,
    ISO 42001, and OWASP Top 10.
    """

    def __init__(self):
        self.nist_subcats: List[Dict] = get_all_nist_subcategories()

    # -----------------------------------------------------------------
    # NIST AI RMF
    # -----------------------------------------------------------------

    def map_to_nist_ai_rmf(
        self, vulnerability_categories: List[str]
    ) -> FrameworkMapping:
        """Map found vulnerabilities to NIST AI RMF gaps.

        Args:
            vulnerability_categories: OWASP IDs that had successful attacks,
                e.g. ["LLM01", "LLM02"].

        Returns:
            FrameworkMapping with one FrameworkGap per affected subcategory.
        """
        total_subcats = len(self.nist_subcats)
        affected: Dict[str, List[str]] = {}  # sub_id -> list of triggering OWASP IDs

        for owasp_id in vulnerability_categories:
            mapped_subs = OWASP_TO_NIST_MAPPING.get(owasp_id, [])
            for sub_id in mapped_subs:
                affected.setdefault(sub_id, []).append(owasp_id)

        gaps: List[FrameworkGap] = []
        for sub_id, triggers in sorted(affected.items()):
            sc = _lookup_nist_subcategory(sub_id, self.nist_subcats)
            if sc is None:
                continue

            # Severity: HIGH if triggered by multiple categories or any HIGH-severity
            # OWASP category; otherwise MEDIUM.
            severity = "HIGH" if len(triggers) > 1 or any(
                OWASP_LLM_TOP_10.get(t, {}).get("severity") == "HIGH"
                for t in triggers
            ) else "MEDIUM"

            owasp_names = ", ".join(
                f"{t} ({OWASP_LLM_TOP_10.get(t, {}).get('name', t)})"
                for t in triggers
            )
            gaps.append(FrameworkGap(
                framework="NIST AI RMF",
                control_id=sub_id,
                control_name=f"{sc['category_name']} — {sub_id}",
                gap_description=(
                    f"Subcategory {sub_id} requirement not met: "
                    f"\"{sc['requirement']}\" "
                    f"Triggered by vulnerabilities in {owasp_names}."
                ),
                severity=severity,
                triggered_by=list(triggers),
                remediation=sc.get("remediation", ""),
            ))

        affected_count = len(affected)
        compliance = (
            (total_subcats - affected_count) / total_subcats * 100
            if total_subcats > 0
            else 100.0
        )

        return FrameworkMapping(
            framework="NIST AI RMF",
            total_controls=total_subcats,
            assessed_controls=affected_count,
            gaps_found=len(gaps),
            compliance_percentage=compliance,
            gaps=gaps,
        )

    # -----------------------------------------------------------------
    # EU AI ACT
    # -----------------------------------------------------------------

    def map_to_eu_ai_act(
        self, vulnerability_categories: List[str], risk_tier: str
    ) -> FrameworkMapping:
        """Map vulnerabilities to EU AI Act obligations.

        Different gap sets apply depending on the risk tier:
        - HIGH: full obligation set (10 requirements); any matched vulnerability
          triggers gaps in the corresponding requirements.
        - LIMITED: gaps only in transparency obligations.
        - MINIMAL: gaps only in voluntary code-of-conduct areas.
        - UNACCEPTABLE: system should not be deployed at all.

        Args:
            vulnerability_categories: OWASP IDs with successful exploits.
            risk_tier: One of "UNACCEPTABLE", "HIGH", "LIMITED", "MINIMAL".

        Returns:
            FrameworkMapping for the EU AI Act.
        """
        tier = risk_tier.upper()
        tier_info = EU_AI_ACT_RISK_TIERS.get(tier, EU_AI_ACT_RISK_TIERS["HIGH"])
        requirements = tier_info.get("requirements", [])
        total_reqs = len(requirements)
        gaps: List[FrameworkGap] = []

        if tier == "UNACCEPTABLE":
            # The system itself is a gap — it should not exist.
            gaps.append(FrameworkGap(
                framework="EU AI Act",
                control_id="Article-5",
                control_name="Prohibited AI Practices",
                gap_description=(
                    "This AI system falls under the UNACCEPTABLE risk tier and "
                    "is prohibited under EU AI Act Article 5."
                ),
                severity="HIGH",
                triggered_by=list(vulnerability_categories),
                remediation="Cease deployment of this AI system within the EU or redesign to exit the prohibited category.",
            ))
            return FrameworkMapping(
                framework="EU AI Act",
                total_controls=1,
                assessed_controls=1,
                gaps_found=1,
                compliance_percentage=0.0,
                gaps=gaps,
            )

        if tier == "HIGH":
            affected_indices: Dict[int, List[str]] = {}
            for owasp_id in vulnerability_categories:
                for idx in OWASP_TO_EU_HIGH_MAPPING.get(owasp_id, []):
                    if idx < total_reqs:
                        affected_indices.setdefault(idx, []).append(owasp_id)

            for idx, triggers in sorted(affected_indices.items()):
                req_text = requirements[idx]
                severity = "HIGH" if len(triggers) > 1 or any(
                    OWASP_LLM_TOP_10.get(t, {}).get("severity") == "HIGH"
                    for t in triggers
                ) else "MEDIUM"
                gaps.append(FrameworkGap(
                    framework="EU AI Act",
                    control_id=f"HIGH-REQ-{idx + 1}",
                    control_name=req_text[:80],
                    gap_description=(
                        f"EU AI Act HIGH-risk requirement not met: \"{req_text}\". "
                        f"Triggered by OWASP categories: {', '.join(triggers)}."
                    ),
                    severity=severity,
                    triggered_by=list(triggers),
                    remediation=f"Implement controls to satisfy: {req_text}",
                ))

        elif tier == "LIMITED":
            # Only transparency obligations are relevant.
            if vulnerability_categories:
                for i, req_text in enumerate(requirements):
                    gaps.append(FrameworkGap(
                        framework="EU AI Act",
                        control_id=f"LIMITED-REQ-{i + 1}",
                        control_name=req_text[:80],
                        gap_description=(
                            f"Transparency obligation not met: \"{req_text}\". "
                            f"Vulnerabilities found in: {', '.join(vulnerability_categories)}."
                        ),
                        severity="MEDIUM",
                        triggered_by=list(vulnerability_categories),
                        remediation=f"Address transparency requirement: {req_text}",
                    ))

        elif tier == "MINIMAL":
            # Only voluntary code of conduct.
            if vulnerability_categories:
                for i, req_text in enumerate(requirements):
                    gaps.append(FrameworkGap(
                        framework="EU AI Act",
                        control_id=f"MINIMAL-REQ-{i + 1}",
                        control_name=req_text[:80],
                        gap_description=(
                            f"Voluntary code of conduct gap: \"{req_text}\". "
                            f"Vulnerabilities found in: {', '.join(vulnerability_categories)}."
                        ),
                        severity="LOW",
                        triggered_by=list(vulnerability_categories),
                        remediation=f"Consider adopting voluntary measure: {req_text}",
                    ))

        gap_count = len(gaps)
        compliance = (
            (total_reqs - gap_count) / total_reqs * 100
            if total_reqs > 0
            else 100.0
        )

        return FrameworkMapping(
            framework="EU AI Act",
            total_controls=total_reqs,
            assessed_controls=gap_count,
            gaps_found=gap_count,
            compliance_percentage=compliance,
            gaps=gaps,
        )

    # -----------------------------------------------------------------
    # ISO 42001
    # -----------------------------------------------------------------

    def map_to_iso_42001(
        self, vulnerability_categories: List[str]
    ) -> FrameworkMapping:
        """Map vulnerabilities to ISO 42001 control gaps.

        Args:
            vulnerability_categories: OWASP IDs with successful exploits.

        Returns:
            FrameworkMapping for ISO 42001.
        """
        # Count total ISO objectives across all topics.
        total_objectives = sum(
            len(topic["objectives"]) for topic in ISO_42001_CONTROLS.values()
        )

        affected: Dict[str, List[str]] = {}  # objective_id -> triggering OWASP IDs

        for owasp_id in vulnerability_categories:
            mapped_objs = OWASP_TO_ISO_MAPPING.get(owasp_id, [])
            for obj_id in mapped_objs:
                affected.setdefault(obj_id, []).append(owasp_id)

        gaps: List[FrameworkGap] = []
        for obj_id, triggers in sorted(affected.items()):
            obj_data = _lookup_iso_objective(obj_id)
            if obj_data is None:
                continue

            severity = "HIGH" if len(triggers) > 1 or any(
                OWASP_LLM_TOP_10.get(t, {}).get("severity") == "HIGH"
                for t in triggers
            ) else "MEDIUM"

            owasp_names = ", ".join(
                f"{t} ({OWASP_LLM_TOP_10.get(t, {}).get('name', t)})"
                for t in triggers
            )
            gaps.append(FrameworkGap(
                framework="ISO 42001",
                control_id=obj_id,
                control_name=obj_data.get("objective", obj_id),
                gap_description=(
                    f"ISO 42001 objective {obj_id} not satisfied: "
                    f"\"{obj_data.get('objective', '')}\". "
                    f"Triggered by {owasp_names}."
                ),
                severity=severity,
                triggered_by=list(triggers),
                remediation=obj_data.get("guidance", ""),
            ))

        affected_count = len(affected)
        compliance = (
            (total_objectives - affected_count) / total_objectives * 100
            if total_objectives > 0
            else 100.0
        )

        return FrameworkMapping(
            framework="ISO 42001",
            total_controls=total_objectives,
            assessed_controls=affected_count,
            gaps_found=len(gaps),
            compliance_percentage=compliance,
            gaps=gaps,
        )

    # -----------------------------------------------------------------
    # OWASP TOP 10 (Direct)
    # -----------------------------------------------------------------

    def map_to_owasp(
        self, suite_results: Dict[str, dict]
    ) -> FrameworkMapping:
        """Map directly from OWASP test results to the OWASP framework.

        Args:
            suite_results: dict like
                {"LLM01": {"total": 20, "vulnerabilities": 5}, ...}
                Each value must contain at least "total" and "vulnerabilities".

        Returns:
            FrameworkMapping for OWASP Top 10.
        """
        total_categories = len(OWASP_LLM_TOP_10)
        gaps: List[FrameworkGap] = []

        for cat_id, cat_info in OWASP_LLM_TOP_10.items():
            result = suite_results.get(cat_id, {})
            vuln_count = result.get("vulnerabilities", 0)
            test_count = result.get("total", 0)

            if vuln_count > 0:
                severity = cat_info.get("severity", "MEDIUM")
                mitigations = cat_info.get("mitigations", [])
                remediation_text = "; ".join(mitigations) if mitigations else ""

                gaps.append(FrameworkGap(
                    framework="OWASP",
                    control_id=cat_id,
                    control_name=cat_info.get("name", cat_id),
                    gap_description=(
                        f"{vuln_count} of {test_count} tests revealed "
                        f"vulnerabilities in {cat_id} "
                        f"({cat_info.get('name', '')}). "
                        f"Impact: {cat_info.get('impact', 'N/A')}"
                    ),
                    severity=severity,
                    triggered_by=[cat_id],
                    remediation=remediation_text,
                ))

        gap_count = len(gaps)
        compliance = (
            (total_categories - gap_count) / total_categories * 100
            if total_categories > 0
            else 100.0
        )

        return FrameworkMapping(
            framework="OWASP",
            total_controls=total_categories,
            assessed_controls=len(suite_results),
            gaps_found=gap_count,
            compliance_percentage=compliance,
            gaps=gaps,
        )

    # -----------------------------------------------------------------
    # UNIFIED MAPPING
    # -----------------------------------------------------------------

    def generate_unified_mapping(
        self,
        vulnerability_categories: List[str],
        suite_results: Dict[str, dict],
        risk_tier: str = "HIGH",
        target_system: str = "",
    ) -> UnifiedMapping:
        """Generate a complete cross-framework compliance mapping.

        Args:
            vulnerability_categories: OWASP IDs with confirmed vulnerabilities.
            suite_results: Per-category test tallies for direct OWASP mapping.
            risk_tier: EU AI Act risk tier (default "HIGH").
            target_system: Name or identifier of the assessed system.

        Returns:
            UnifiedMapping aggregating all four framework assessments.
        """
        nist = self.map_to_nist_ai_rmf(vulnerability_categories)
        eu = self.map_to_eu_ai_act(vulnerability_categories, risk_tier)
        iso = self.map_to_iso_42001(vulnerability_categories)
        owasp = self.map_to_owasp(suite_results)

        # Overall compliance is the simple average across frameworks.
        framework_scores = [
            nist.compliance_percentage,
            eu.compliance_percentage,
            iso.compliance_percentage,
            owasp.compliance_percentage,
        ]
        overall = sum(framework_scores) / len(framework_scores)

        # Collect all gaps and select the top 10 most critical.
        all_gaps: List[FrameworkGap] = (
            nist.gaps + eu.gaps + iso.gaps + owasp.gaps
        )
        priority_gaps = self._select_priority_gaps(all_gaps, top_n=10)

        return UnifiedMapping(
            assessment_date=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            target_system=target_system,
            risk_tier=risk_tier.upper(),
            nist_mapping=nist,
            eu_mapping=eu,
            iso_mapping=iso,
            owasp_mapping=owasp,
            overall_compliance=overall,
            priority_gaps=priority_gaps,
        )

    # -----------------------------------------------------------------
    # CONVENIENCE BRIDGES (called by AssessmentEngine)
    # -----------------------------------------------------------------

    def map_from_red_team(
        self, red_team_results, system_name: str = ""
    ) -> UnifiedMapping:
        """Build a unified mapping from ``AssessmentResults``.

        Extracts vulnerability categories and per-category tallies, then
        delegates to :meth:`generate_unified_mapping`.
        """
        vuln_cats: List[str] = []
        suite_dict: Dict[str, dict] = {}

        for owasp_id, sr in (red_team_results.suite_results or {}).items():
            total = getattr(sr, "total_attacks", 0)
            vulns = getattr(sr, "successful_attacks", 0)
            suite_dict[owasp_id] = {"total": total, "vulnerabilities": vulns}
            if vulns > 0:
                vuln_cats.append(owasp_id)

        return self.generate_unified_mapping(
            vulnerability_categories=vuln_cats,
            suite_results=suite_dict,
            risk_tier="HIGH",
            target_system=system_name,
        )

    def map_from_findings(
        self, gap_refs: List[str], system_name: str = ""
    ) -> UnifiedMapping:
        """Build a unified mapping from documentation audit gap references.

        Translates framework-ref strings (e.g. ``"GOVERN-1.1"``) into a set
        of synthetic OWASP-like vulnerability categories so the normal mapping
        pipeline can run.
        """
        # Reverse-map framework refs back to OWASP categories
        from ai_frameworks import OWASP_LLM_TOP_10
        vuln_cats: List[str] = []
        for owasp_id in OWASP_LLM_TOP_10:
            nist_refs = OWASP_TO_NIST_MAPPING.get(owasp_id, [])
            iso_refs = OWASP_TO_ISO_MAPPING.get(owasp_id, [])
            all_refs = nist_refs + iso_refs
            if any(ref in gap_refs for ref in all_refs):
                vuln_cats.append(owasp_id)

        # Build a minimal suite_results dict for owasp mapper
        suite_dict: Dict[str, dict] = {}
        for cat in vuln_cats:
            suite_dict[cat] = {"total": 1, "vulnerabilities": 1}

        return self.generate_unified_mapping(
            vulnerability_categories=vuln_cats,
            suite_results=suite_dict,
            risk_tier="HIGH",
            target_system=system_name,
        )

    # -----------------------------------------------------------------
    # REMEDIATION ROADMAP
    # -----------------------------------------------------------------

    def get_remediation_roadmap(
        self, mapping: UnifiedMapping
    ) -> List[Dict]:
        """Generate a prioritised remediation roadmap from a unified mapping.

        Returns a list of dicts, each containing:
            priority  : int (1 = highest)
            gap       : FrameworkGap (serialised)
            effort    : str ("LOW" / "MEDIUM" / "HIGH")
            impact    : str ("LOW" / "MEDIUM" / "HIGH")
            recommendation : str
        """
        all_gaps: List[FrameworkGap] = (
            (mapping.nist_mapping.gaps if mapping.nist_mapping else [])
            + (mapping.eu_mapping.gaps if mapping.eu_mapping else [])
            + (mapping.iso_mapping.gaps if mapping.iso_mapping else [])
            + (mapping.owasp_mapping.gaps if mapping.owasp_mapping else [])
        )

        # Sort by severity descending, then by number of triggering categories
        # descending (more triggers = broader systemic issue).
        sorted_gaps = sorted(
            all_gaps,
            key=lambda g: (_severity_rank(g.severity), len(g.triggered_by)),
            reverse=True,
        )

        roadmap: List[Dict] = []
        for idx, gap in enumerate(sorted_gaps, start=1):
            effort = self._estimate_effort(gap)
            impact = self._estimate_impact(gap)
            recommendation = self._build_recommendation(gap)

            roadmap.append({
                "priority": idx,
                "gap": gap.to_dict(),
                "effort": effort,
                "impact": impact,
                "recommendation": recommendation,
            })

        return roadmap

    # -----------------------------------------------------------------
    # INTERNAL HELPERS
    # -----------------------------------------------------------------

    @staticmethod
    def _select_priority_gaps(
        gaps: List[FrameworkGap], top_n: int = 10
    ) -> List[FrameworkGap]:
        """Return the top-N most critical gaps.

        Sorting criteria:
        1. Severity (HIGH > MEDIUM > LOW)
        2. Number of triggering OWASP categories (more = broader risk)
        """
        return sorted(
            gaps,
            key=lambda g: (_severity_rank(g.severity), len(g.triggered_by)),
            reverse=True,
        )[:top_n]

    @staticmethod
    def _estimate_effort(gap: FrameworkGap) -> str:
        """Heuristic effort estimate based on the gap's framework and scope."""
        if gap.framework == "EU AI Act" and gap.severity == "HIGH":
            return "HIGH"
        if gap.framework == "NIST AI RMF" and len(gap.triggered_by) > 2:
            return "HIGH"
        if gap.severity == "HIGH":
            return "MEDIUM"
        if gap.severity == "MEDIUM":
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _estimate_impact(gap: FrameworkGap) -> str:
        """Heuristic impact estimate — remediating this gap would have X impact."""
        trigger_count = len(gap.triggered_by)
        if gap.severity == "HIGH" and trigger_count >= 2:
            return "HIGH"
        if gap.severity == "HIGH" or trigger_count >= 2:
            return "HIGH"
        if gap.severity == "MEDIUM":
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _build_recommendation(gap: FrameworkGap) -> str:
        """Build a human-readable remediation recommendation."""
        parts = [f"[{gap.framework}] Address {gap.control_id}"]
        if gap.remediation:
            parts.append(f": {gap.remediation}")
        if len(gap.triggered_by) > 1:
            parts.append(
                f" This gap is triggered by {len(gap.triggered_by)} OWASP "
                f"categories ({', '.join(gap.triggered_by)}), indicating a "
                f"systemic issue that should be prioritised."
            )
        return "".join(parts)
