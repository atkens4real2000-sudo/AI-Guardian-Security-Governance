"""
AI Guardian Assessment Engine - Core Orchestration Module.

Manages the GuardianAssessment lifecycle: create assessments, run live red team
tests or documentation audits, calculate risk scores and compliance grades,
and export/import assessment results as JSON.

Usage:
    from assessment_engine import AssessmentEngine

    engine = AssessmentEngine()
    assessment = engine.create_assessment("Acme Corp", "ChatBot v2")
    assessment = engine.run_documentation_audit(assessment, responses={...})
    engine.export_assessment(assessment, "acme_assessment.json")

Author: Akintade Akinokun
"""

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from red_team_engine import RedTeamEngine, AssessmentResults, AttackResult, SuiteResult
from risk_classifier import RiskClassifier, RiskClassification
from governance_mapper import GovernanceMapper, UnifiedMapping, FrameworkMapping, FrameworkGap
from llm_connectors import LLMConnector, create_connector
from ai_frameworks import get_framework_summary, OWASP_LLM_TOP_10

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Terminal Colors
# ---------------------------------------------------------------------------

class Colors:
    """ANSI escape codes for terminal output."""
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


GRADE_COLORS = {
    "A": Colors.GREEN,
    "B": Colors.GREEN,
    "C": Colors.YELLOW,
    "D": Colors.RED,
    "F": Colors.RED,
    "N/A": Colors.DIM,
}


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class DocumentationFinding:
    """Result of evaluating a single documentation audit question."""
    question_id: str
    question: str
    response: str               # User's answer
    assessment: str             # ADEQUATE / PARTIAL / INADEQUATE / NOT_ASSESSED
    framework_refs: List[str]   # Framework controls this maps to
    notes: str = ""


@dataclass
class GuardianAssessment:
    """Complete assessment record for an AI system.

    Collects risk classification, red team results, governance mappings,
    documentation findings, and calculated scores into a single exportable
    object.
    """
    assessment_id: str
    organization: str
    system_name: str
    system_description: str
    created_at: str
    assessor: str
    assessment_mode: str = "docs"  # "live" / "docs" / "agent"

    # Results (populated during assessment)
    risk_classification: Optional[RiskClassification] = None
    red_team_results: Optional[AssessmentResults] = None
    governance_mapping: Optional[UnifiedMapping] = None
    documentation_findings: List[DocumentationFinding] = field(default_factory=list)

    # Scores (calculated after assessment)
    overall_risk_score: float = 0.0          # 0-100 (higher = more risk)
    security_posture_grade: str = "N/A"      # A-F
    compliance_scores: Dict[str, float] = field(default_factory=dict)  # {framework: %}

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict:
        """Serialize entire assessment to dict for JSON export."""
        data: Dict = {
            "assessment_id": self.assessment_id,
            "organization": self.organization,
            "system_name": self.system_name,
            "system_description": self.system_description,
            "created_at": self.created_at,
            "assessor": self.assessor,
            "assessment_mode": self.assessment_mode,
            "overall_risk_score": self.overall_risk_score,
            "security_posture_grade": self.security_posture_grade,
            "compliance_scores": dict(self.compliance_scores),
        }

        # Risk classification
        if self.risk_classification is not None:
            rc = self.risk_classification
            data["risk_classification"] = {
                "tier": rc.tier,
                "confidence": rc.confidence,
                "reasons": list(rc.reasons),
                "obligations": list(rc.obligations),
                "article_references": list(rc.article_references),
                "risk_factors": dict(rc.risk_factors),
                "recommendations": list(rc.recommendations),
            }
        else:
            data["risk_classification"] = None

        # Red team results
        if self.red_team_results is not None:
            data["red_team_results"] = self.red_team_results.to_dict()
        else:
            data["red_team_results"] = None

        # Governance mapping
        if self.governance_mapping is not None:
            data["governance_mapping"] = self.governance_mapping.to_dict()
        else:
            data["governance_mapping"] = None

        # Documentation findings
        data["documentation_findings"] = [
            {
                "question_id": f.question_id,
                "question": f.question,
                "response": f.response,
                "assessment": f.assessment,
                "framework_refs": list(f.framework_refs),
                "notes": f.notes,
            }
            for f in self.documentation_findings
        ]

        return data

    @classmethod
    def from_dict(cls, data: Dict) -> "GuardianAssessment":
        """Deserialize from dict."""
        assessment = cls(
            assessment_id=data["assessment_id"],
            organization=data["organization"],
            system_name=data["system_name"],
            system_description=data.get("system_description", ""),
            created_at=data["created_at"],
            assessor=data.get("assessor", ""),
            assessment_mode=data.get("assessment_mode", "docs"),
            overall_risk_score=data.get("overall_risk_score", 0.0),
            security_posture_grade=data.get("security_posture_grade", "N/A"),
            compliance_scores=data.get("compliance_scores", {}),
        )

        # Restore risk classification
        rc_data = data.get("risk_classification")
        if rc_data is not None:
            assessment.risk_classification = RiskClassification(
                tier=rc_data["tier"],
                confidence=rc_data["confidence"],
                reasons=rc_data.get("reasons", []),
                obligations=rc_data.get("obligations", []),
                article_references=rc_data.get("article_references", []),
                risk_factors=rc_data.get("risk_factors", {}),
                recommendations=rc_data.get("recommendations", []),
            )

        # Restore red team results (flat reconstruction)
        rt_data = data.get("red_team_results")
        if rt_data is not None:
            suite_results: Dict[str, SuiteResult] = {}
            for cat_id, sr_dict in rt_data.get("suite_results", {}).items():
                results_list = [
                    AttackResult(
                        attack_id=r["attack_id"],
                        category=r["category"],
                        attack_name=r["attack_name"],
                        payload_sent=r["payload_sent"],
                        response_received=r["response_received"],
                        success=r["success"],
                        severity=r["severity"],
                        confidence=r["confidence"],
                        detection_reason=r["detection_reason"],
                        latency_ms=r.get("latency_ms", 0.0),
                    )
                    for r in sr_dict.get("results", [])
                ]
                suite_results[cat_id] = SuiteResult(
                    category=sr_dict["category"],
                    total_attacks=sr_dict["total_attacks"],
                    successful_attacks=sr_dict["successful_attacks"],
                    results=results_list,
                )
            assessment.red_team_results = AssessmentResults(
                target_model=rt_data.get("target_model", "unknown"),
                assessment_date=rt_data.get("assessment_date", ""),
                total_attacks=rt_data.get("total_attacks", 0),
                total_vulnerabilities=rt_data.get("total_vulnerabilities", 0),
                suite_results=suite_results,
                high_severity_count=rt_data.get("high_severity_count", 0),
                medium_severity_count=rt_data.get("medium_severity_count", 0),
                low_severity_count=rt_data.get("low_severity_count", 0),
            )

        # Restore governance mapping
        gm_data = data.get("governance_mapping")
        if gm_data is not None:
            def _restore_fm(raw):
                if raw is None:
                    return None
                gaps = [
                    FrameworkGap(**g) if isinstance(g, dict) else g
                    for g in raw.get("gaps", [])
                ]
                return FrameworkMapping(
                    framework=raw["framework"],
                    total_controls=raw["total_controls"],
                    assessed_controls=raw["assessed_controls"],
                    gaps_found=raw.get("gaps_found", len(gaps)),
                    compliance_percentage=raw["compliance_percentage"],
                    gaps=gaps,
                )

            priority_gaps = [
                FrameworkGap(**g) if isinstance(g, dict) else g
                for g in gm_data.get("priority_gaps", [])
            ]
            assessment.governance_mapping = UnifiedMapping(
                assessment_date=gm_data.get("assessment_date", ""),
                target_system=gm_data.get("target_system", ""),
                risk_tier=gm_data.get("risk_tier", ""),
                nist_mapping=_restore_fm(gm_data.get("nist_mapping")),
                eu_mapping=_restore_fm(gm_data.get("eu_mapping")),
                iso_mapping=_restore_fm(gm_data.get("iso_mapping")),
                owasp_mapping=_restore_fm(gm_data.get("owasp_mapping")),
                overall_compliance=gm_data.get("overall_compliance", 0.0),
                priority_gaps=priority_gaps,
            )

        # Restore documentation findings
        for f_data in data.get("documentation_findings", []):
            assessment.documentation_findings.append(
                DocumentationFinding(
                    question_id=f_data["question_id"],
                    question=f_data["question"],
                    response=f_data["response"],
                    assessment=f_data["assessment"],
                    framework_refs=f_data.get("framework_refs", []),
                    notes=f_data.get("notes", ""),
                )
            )

        return assessment


# ---------------------------------------------------------------------------
# Assessment Engine
# ---------------------------------------------------------------------------

class AssessmentEngine:
    """Core orchestration engine for AI Guardian assessments.

    Supports three assessment modes:
      - **docs**: Documentation-based audit via questionnaire
      - **live**: Live red team assessment against an LLM endpoint
      - **agent**: Agent-focused assessment (LLM06 Excessive Agency)
    """

    # ------------------------------------------------------------------
    # Documentation audit questions
    # ------------------------------------------------------------------

    DOC_AUDIT_QUESTIONS = [
        {
            "id": "gov_policy",
            "question": "Does your organization have a formal AI governance policy?",
            "framework_refs": ["GOVERN-1.1", "A.2.2"],
            "adequate_indicators": ["yes", "formal", "documented", "approved"],
        },
        {
            "id": "risk_assessment",
            "question": "Is there a process for assessing AI system risks before deployment?",
            "framework_refs": ["GOVERN-1.3", "MAP-4.1", "A.5.2"],
            "adequate_indicators": ["yes", "process", "systematic", "before deployment"],
        },
        {
            "id": "roles_accountability",
            "question": "Are roles and responsibilities for AI governance clearly defined?",
            "framework_refs": ["GOVERN-2.1", "A.3.2"],
            "adequate_indicators": ["yes", "defined", "raci", "assigned"],
        },
        {
            "id": "training",
            "question": "Do AI team members receive regular AI ethics and risk training?",
            "framework_refs": ["GOVERN-2.2", "A.4.5"],
            "adequate_indicators": ["yes", "regular", "training", "annual"],
        },
        {
            "id": "data_governance",
            "question": "Is there a data governance framework for AI training and operational data?",
            "framework_refs": ["MAP-2.1", "A.7.2", "A.7.3"],
            "adequate_indicators": ["yes", "framework", "governance", "quality"],
        },
        {
            "id": "bias_testing",
            "question": "Are AI systems tested for bias and fairness before and after deployment?",
            "framework_refs": ["MEASURE-2.2", "A.5.2", "A.6.3"],
            "adequate_indicators": ["yes", "tested", "bias", "fairness", "regular"],
        },
        {
            "id": "security_testing",
            "question": "Are AI systems tested for adversarial robustness and security?",
            "framework_refs": ["MEASURE-2.5", "A.6.3"],
            "adequate_indicators": ["yes", "red team", "adversarial", "penetration", "security"],
        },
        {
            "id": "monitoring",
            "question": "Are deployed AI systems continuously monitored for drift and anomalies?",
            "framework_refs": ["MEASURE-2.4", "A.9.3"],
            "adequate_indicators": ["yes", "monitoring", "continuous", "drift", "alerts"],
        },
        {
            "id": "incident_response",
            "question": "Is there an AI-specific incident response plan?",
            "framework_refs": ["MANAGE-2.3", "GOVERN-6.2", "GOVERN-4.1"],
            "adequate_indicators": ["yes", "plan", "incident", "response", "playbook"],
        },
        {
            "id": "transparency",
            "question": "Are users informed when they interact with AI systems?",
            "framework_refs": ["MAP-1.1", "A.8.2", "A.8.3"],
            "adequate_indicators": ["yes", "informed", "disclosure", "transparent"],
        },
        {
            "id": "human_oversight",
            "question": "Is human oversight implemented for AI-driven decisions?",
            "framework_refs": ["MANAGE-1.1", "A.9.4"],
            "adequate_indicators": ["yes", "human", "oversight", "review", "override"],
        },
        {
            "id": "third_party",
            "question": "Are third-party AI components and vendors assessed for risk?",
            "framework_refs": ["GOVERN-3.2", "GOVERN-6.1", "A.10.2"],
            "adequate_indicators": ["yes", "assessed", "vendor", "third-party", "audit"],
        },
        {
            "id": "documentation",
            "question": "Is AI system documentation maintained (model cards, design docs, limitations)?",
            "framework_refs": ["MAP-2.2", "A.6.6"],
            "adequate_indicators": ["yes", "documentation", "model card", "maintained"],
        },
        {
            "id": "decommission",
            "question": "Are there procedures for decommissioning or phasing out AI systems?",
            "framework_refs": ["MANAGE-2.4", "A.6.5"],
            "adequate_indicators": ["yes", "procedure", "decommission", "phase out", "retirement"],
        },
        {
            "id": "eu_compliance",
            "question": "Has the AI system been classified under the EU AI Act risk tiers?",
            "framework_refs": ["GOVERN-1.1"],
            "adequate_indicators": ["yes", "classified", "eu ai act", "risk tier"],
        },
    ]

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def __init__(self):
        self.risk_classifier = RiskClassifier()
        self.governance_mapper = GovernanceMapper()

    # ------------------------------------------------------------------
    # Assessment creation
    # ------------------------------------------------------------------

    def create_assessment(
        self,
        organization: str,
        system_name: str,
        description: str = "",
        assessor: str = "",
        mode: str = "docs",
    ) -> GuardianAssessment:
        """Create a new assessment with unique ID and timestamp.

        Args:
            organization: Name of the assessed organization.
            system_name: Name of the AI system being assessed.
            description: Free-text description of the AI system.
            assessor: Name or identifier of the person running the assessment.
            mode: Assessment mode - ``"docs"``, ``"live"``, or ``"agent"``.

        Returns:
            A fresh ``GuardianAssessment`` ready for execution.
        """
        assessment_id = str(uuid.uuid4())[:8]
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        assessment = GuardianAssessment(
            assessment_id=assessment_id,
            organization=organization,
            system_name=system_name,
            system_description=description,
            created_at=created_at,
            assessor=assessor,
            assessment_mode=mode,
        )

        logger.info(
            "Created assessment %s for %s / %s (mode=%s)",
            assessment_id, organization, system_name, mode,
        )
        print(
            f"\n{Colors.GREEN}[+]{Colors.RESET} Assessment {Colors.BOLD}{assessment_id}{Colors.RESET} "
            f"created for {Colors.CYAN}{organization}{Colors.RESET} - "
            f"{Colors.CYAN}{system_name}{Colors.RESET}"
        )

        return assessment

    # ------------------------------------------------------------------
    # Live assessment (red team against an LLM endpoint)
    # ------------------------------------------------------------------

    def run_live_assessment(
        self,
        assessment: GuardianAssessment,
        connector: LLMConnector,
        categories: List[str] = None,
        system_prompt: str = "",
    ) -> GuardianAssessment:
        """Run live red team assessment against an LLM.

        Steps:
          1. Run risk classification (interactive)
          2. Run red team engine with specified categories
          3. Generate governance mapping from findings
          4. Calculate scores

        Args:
            assessment: The ``GuardianAssessment`` to populate.
            connector: An initialised ``LLMConnector`` for the target LLM.
            categories: Optional list of OWASP IDs (e.g. ``["LLM01", "LLM02"]``).
                        If *None*, all available categories are run.
            system_prompt: The target system's system prompt (used for leakage testing).

        Returns:
            The updated ``GuardianAssessment``.
        """
        assessment.assessment_mode = "live"
        model_info = connector.get_model_info()
        model_name = model_info.get("model", "unknown")

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}  AI Guardian - Live Red Team Assessment{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}")
        print(f"  Target: {Colors.CYAN}{model_name}{Colors.RESET}")
        print(f"  System: {Colors.CYAN}{assessment.system_name}{Colors.RESET}")
        print()

        # Step 1: Risk classification
        print(f"{Colors.BOLD}[1/4] Running EU AI Act risk classification...{Colors.RESET}")
        try:
            assessment.risk_classification = self.risk_classifier.classify_interactive()
        except (SystemExit, KeyboardInterrupt):
            print(f"{Colors.YELLOW}  Risk classification skipped.{Colors.RESET}")

        # Step 2: Red team engine
        print(f"\n{Colors.BOLD}[2/4] Running red team attack suites...{Colors.RESET}")
        engine = RedTeamEngine(connector)
        engine.system_prompt = system_prompt
        assessment.red_team_results = engine.run_full_suite(categories=categories)

        rt = assessment.red_team_results
        print(
            f"  {Colors.GREEN}Completed:{Colors.RESET} {rt.total_attacks} attacks, "
            f"{Colors.RED}{rt.total_vulnerabilities} vulnerabilities{Colors.RESET} found"
        )
        print(
            f"  Severity: {Colors.RED}HIGH={rt.high_severity_count}{Colors.RESET}  "
            f"{Colors.YELLOW}MED={rt.medium_severity_count}{Colors.RESET}  "
            f"{Colors.DIM}LOW={rt.low_severity_count}{Colors.RESET}"
        )

        # Step 3: Governance mapping
        print(f"\n{Colors.BOLD}[3/4] Generating governance mapping...{Colors.RESET}")
        assessment.governance_mapping = self.governance_mapper.map_from_red_team(
            assessment.red_team_results,
            system_name=assessment.system_name,
        )

        # Step 4: Calculate scores
        print(f"\n{Colors.BOLD}[4/4] Calculating scores...{Colors.RESET}")
        assessment = self.calculate_scores(assessment)

        self._print_score_summary(assessment)
        return assessment

    # ------------------------------------------------------------------
    # Documentation audit
    # ------------------------------------------------------------------

    def run_documentation_audit(
        self,
        assessment: GuardianAssessment,
        responses: Dict[str, str] = None,
    ) -> GuardianAssessment:
        """Run documentation-based audit.

        If *responses* is ``None``, run interactively (prompt user for each
        question via stdin).  If *responses* is a dict mapping question_id to
        answer string, evaluate programmatically.

        Args:
            assessment: The ``GuardianAssessment`` to populate.
            responses: Optional pre-filled responses ``{question_id: answer}``.

        Returns:
            The updated ``GuardianAssessment``.
        """
        assessment.assessment_mode = "docs"
        interactive = responses is None

        if interactive:
            print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}")
            print(f"{Colors.BOLD}  AI Guardian - Documentation Audit{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}")
            print(f"  Organization: {Colors.CYAN}{assessment.organization}{Colors.RESET}")
            print(f"  System:       {Colors.CYAN}{assessment.system_name}{Colors.RESET}")
            print(f"\n{Colors.DIM}  Answer each question with a description of your current practices.{Colors.RESET}")
            print(f"{Colors.DIM}  Press Enter to skip a question.{Colors.RESET}\n")

        assessment.documentation_findings = []

        for idx, question in enumerate(self.DOC_AUDIT_QUESTIONS, start=1):
            qid = question["id"]

            # Get response
            if interactive:
                print(
                    f"{Colors.BOLD}[{idx}/{len(self.DOC_AUDIT_QUESTIONS)}] "
                    f"{question['question']}{Colors.RESET}"
                )
                print(f"  {Colors.DIM}(Maps to: {', '.join(question['framework_refs'])}){Colors.RESET}")
                try:
                    user_response = input(f"  {Colors.CYAN}>{Colors.RESET} ").strip()
                except (EOFError, KeyboardInterrupt):
                    print(f"\n{Colors.YELLOW}Audit cancelled.{Colors.RESET}")
                    break
            else:
                user_response = responses.get(qid, "")

            # Evaluate
            if not user_response:
                evaluation = "NOT_ASSESSED"
            else:
                evaluation = self._evaluate_doc_response(question, user_response)

            finding = DocumentationFinding(
                question_id=qid,
                question=question["question"],
                response=user_response,
                assessment=evaluation,
                framework_refs=list(question["framework_refs"]),
            )
            assessment.documentation_findings.append(finding)

            # Print evaluation in interactive mode
            if interactive and user_response:
                color = {
                    "ADEQUATE": Colors.GREEN,
                    "PARTIAL": Colors.YELLOW,
                    "INADEQUATE": Colors.RED,
                }.get(evaluation, Colors.DIM)
                print(f"  {color}=> {evaluation}{Colors.RESET}\n")
            elif interactive:
                print(f"  {Colors.DIM}=> NOT_ASSESSED (skipped){Colors.RESET}\n")

        # Risk classification
        logger.info("Running risk classification for documentation audit")
        if interactive:
            print(f"\n{Colors.BOLD}Running EU AI Act risk classification...{Colors.RESET}")
            try:
                assessment.risk_classification = self.risk_classifier.classify_interactive()
            except (SystemExit, KeyboardInterrupt):
                print(f"{Colors.YELLOW}  Risk classification skipped.{Colors.RESET}")
        else:
            # For programmatic mode, use a default minimal-risk profile
            assessment.risk_classification = self.risk_classifier.classify_from_profile({
                "purpose": 10,
                "users": 3,
                "autonomy": 3,
                "data_sensitivity": 5,
                "safety_impact": 3,
                "transparency": 2,
                "reversibility": 2,
            })

        # Governance mapping based on inadequate findings
        inadequate_refs: List[str] = []
        for finding in assessment.documentation_findings:
            if finding.assessment in ("INADEQUATE", "PARTIAL"):
                inadequate_refs.extend(finding.framework_refs)

        assessment.governance_mapping = self.governance_mapper.map_from_findings(
            gap_refs=inadequate_refs,
            system_name=assessment.system_name,
        )

        # Calculate scores
        assessment = self.calculate_scores(assessment)
        self._print_score_summary(assessment)
        return assessment

    # ------------------------------------------------------------------
    # Agent-specific assessment
    # ------------------------------------------------------------------

    def run_agent_assessment(
        self,
        assessment: GuardianAssessment,
        connector: LLMConnector,
        system_prompt: str = "",
    ) -> GuardianAssessment:
        """Run agent-specific assessment (focuses on LLM06 Excessive Agency).

        Similar to live assessment but concentrates on agency-related attack
        categories (LLM06 primarily, plus LLM01 and LLM05 which are
        commonly chained in agentic exploits).

        Args:
            assessment: The ``GuardianAssessment`` to populate.
            connector: An initialised ``LLMConnector`` for the agent.
            system_prompt: The agent's system prompt.

        Returns:
            The updated ``GuardianAssessment``.
        """
        assessment.assessment_mode = "agent"
        model_info = connector.get_model_info()
        model_name = model_info.get("model", "unknown")

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}  AI Guardian - Agent Assessment (Excessive Agency){Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}")
        print(f"  Target: {Colors.CYAN}{model_name}{Colors.RESET}")
        print(f"  System: {Colors.CYAN}{assessment.system_name}{Colors.RESET}")
        print()

        # Risk classification
        print(f"{Colors.BOLD}[1/4] Running EU AI Act risk classification...{Colors.RESET}")
        try:
            assessment.risk_classification = self.risk_classifier.classify_interactive()
        except (SystemExit, KeyboardInterrupt):
            print(f"{Colors.YELLOW}  Risk classification skipped.{Colors.RESET}")

        # Red team - agency-focused categories
        agency_categories = ["LLM01", "LLM05", "LLM06"]
        print(f"\n{Colors.BOLD}[2/4] Running agent-focused attack suites ({', '.join(agency_categories)})...{Colors.RESET}")
        engine = RedTeamEngine(connector)
        engine.system_prompt = system_prompt
        assessment.red_team_results = engine.run_full_suite(categories=agency_categories)

        rt = assessment.red_team_results
        print(
            f"  {Colors.GREEN}Completed:{Colors.RESET} {rt.total_attacks} attacks, "
            f"{Colors.RED}{rt.total_vulnerabilities} vulnerabilities{Colors.RESET} found"
        )

        # Governance mapping
        print(f"\n{Colors.BOLD}[3/4] Generating governance mapping...{Colors.RESET}")
        assessment.governance_mapping = self.governance_mapper.map_from_red_team(
            assessment.red_team_results,
            system_name=assessment.system_name,
        )

        # Calculate scores
        print(f"\n{Colors.BOLD}[4/4] Calculating scores...{Colors.RESET}")
        assessment = self.calculate_scores(assessment)

        self._print_score_summary(assessment)
        return assessment

    # ------------------------------------------------------------------
    # Response evaluation
    # ------------------------------------------------------------------

    def _evaluate_doc_response(self, question: dict, response: str) -> str:
        """Evaluate a documentation response against adequate indicators.

        Counts how many ``adequate_indicators`` appear (as substrings) in
        the lowercased response text.

        Returns:
            ``"ADEQUATE"`` if 3+ indicators match,
            ``"PARTIAL"`` if 1-2 match,
            ``"INADEQUATE"`` if 0 match.
        """
        response_lower = response.lower()
        indicators = question.get("adequate_indicators", [])

        matches = sum(1 for ind in indicators if ind in response_lower)

        if matches >= 3:
            return "ADEQUATE"
        elif matches >= 1:
            return "PARTIAL"
        else:
            return "INADEQUATE"

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def calculate_scores(self, assessment: GuardianAssessment) -> GuardianAssessment:
        """Calculate overall risk score, grade, and compliance scores.

        **Risk score (0-100, higher = more risk):**
          - +20 if risk classification tier is HIGH or UNACCEPTABLE
          - +10 per HIGH severity vulnerability from red team results
          - +5 per MEDIUM severity vulnerability
          - +2 per LOW severity vulnerability
          - +5 per INADEQUATE documentation finding
          - +2 per PARTIAL documentation finding
          - Capped at 100

        **Security posture grade:**
          A (0-15), B (16-30), C (31-50), D (51-70), F (71-100)

        **Compliance scores:**
          Derived from governance mapping if available.
        """
        score = 0.0

        # Risk classification contribution
        if assessment.risk_classification is not None:
            tier = assessment.risk_classification.tier.upper()
            if tier in ("HIGH", "UNACCEPTABLE"):
                score += 20

        # Red team vulnerability contributions
        if assessment.red_team_results is not None:
            for suite in assessment.red_team_results.suite_results.values():
                for result in suite.results:
                    if result.success:
                        severity = result.severity.upper()
                        if severity == "HIGH":
                            score += 10
                        elif severity == "MEDIUM":
                            score += 5
                        else:
                            score += 2

        # Documentation finding contributions
        for finding in assessment.documentation_findings:
            if finding.assessment == "INADEQUATE":
                score += 5
            elif finding.assessment == "PARTIAL":
                score += 2

        # Cap at 100
        assessment.overall_risk_score = min(score, 100.0)

        # Determine grade
        if assessment.overall_risk_score <= 15:
            assessment.security_posture_grade = "A"
        elif assessment.overall_risk_score <= 30:
            assessment.security_posture_grade = "B"
        elif assessment.overall_risk_score <= 50:
            assessment.security_posture_grade = "C"
        elif assessment.overall_risk_score <= 70:
            assessment.security_posture_grade = "D"
        else:
            assessment.security_posture_grade = "F"

        # Compliance scores from governance mapping
        if assessment.governance_mapping is not None:
            for name, fm in assessment.governance_mapping.framework_mappings.items():
                assessment.compliance_scores[name] = fm.compliance_percentage

        logger.info(
            "Scores calculated: risk=%.1f, grade=%s",
            assessment.overall_risk_score,
            assessment.security_posture_grade,
        )

        return assessment

    # ------------------------------------------------------------------
    # Export / Import
    # ------------------------------------------------------------------

    def export_assessment(self, assessment: GuardianAssessment, path: str):
        """Save assessment to JSON file.

        Args:
            assessment: The assessment to export.
            path: Filesystem path for the output JSON file.
        """
        data = assessment.to_dict()
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)

        print(
            f"{Colors.GREEN}[+]{Colors.RESET} Assessment exported to "
            f"{Colors.BOLD}{path}{Colors.RESET}"
        )
        logger.info("Assessment %s exported to %s", assessment.assessment_id, path)

    @staticmethod
    def import_assessment(path: str) -> GuardianAssessment:
        """Load assessment from JSON file.

        Args:
            path: Filesystem path to the JSON file.

        Returns:
            Reconstructed ``GuardianAssessment``.
        """
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        assessment = GuardianAssessment.from_dict(data)
        print(
            f"{Colors.GREEN}[+]{Colors.RESET} Assessment {Colors.BOLD}{assessment.assessment_id}{Colors.RESET} "
            f"loaded from {Colors.DIM}{path}{Colors.RESET}"
        )
        logger.info("Assessment %s imported from %s", assessment.assessment_id, path)
        return assessment

    # ------------------------------------------------------------------
    # Summary for dashboard
    # ------------------------------------------------------------------

    def get_assessment_summary(self, assessment: GuardianAssessment) -> Dict:
        """Return summary dict suitable for dashboard display.

        Returns:
            Dict with keys: assessment_id, organization, system_name,
            mode, created_at, risk_score, grade, risk_tier, total_vulns,
            doc_findings_summary, compliance_scores, framework_summary.
        """
        # Documentation findings summary
        doc_counts = {"ADEQUATE": 0, "PARTIAL": 0, "INADEQUATE": 0, "NOT_ASSESSED": 0}
        for f in assessment.documentation_findings:
            doc_counts[f.assessment] = doc_counts.get(f.assessment, 0) + 1

        # Vulnerability counts
        total_vulns = 0
        vuln_by_severity = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        if assessment.red_team_results is not None:
            total_vulns = assessment.red_team_results.total_vulnerabilities
            vuln_by_severity["HIGH"] = assessment.red_team_results.high_severity_count
            vuln_by_severity["MEDIUM"] = assessment.red_team_results.medium_severity_count
            vuln_by_severity["LOW"] = assessment.red_team_results.low_severity_count

        return {
            "assessment_id": assessment.assessment_id,
            "organization": assessment.organization,
            "system_name": assessment.system_name,
            "mode": assessment.assessment_mode,
            "created_at": assessment.created_at,
            "risk_score": assessment.overall_risk_score,
            "grade": assessment.security_posture_grade,
            "risk_tier": (
                assessment.risk_classification.tier
                if assessment.risk_classification else "NOT_CLASSIFIED"
            ),
            "total_vulnerabilities": total_vulns,
            "vulnerabilities_by_severity": vuln_by_severity,
            "doc_findings_summary": doc_counts,
            "compliance_scores": dict(assessment.compliance_scores),
            "framework_summary": get_framework_summary(),
        }

    # ------------------------------------------------------------------
    # Internal display helpers
    # ------------------------------------------------------------------

    def _print_score_summary(self, assessment: GuardianAssessment):
        """Print a formatted score summary to the terminal."""
        grade = assessment.security_posture_grade
        grade_color = GRADE_COLORS.get(grade, Colors.RESET)

        print(f"\n{Colors.BOLD}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}  Assessment Results - {assessment.system_name}{Colors.RESET}")
        print(f"{Colors.BOLD}{'=' * 60}{Colors.RESET}")
        print(
            f"  Risk Score:  {Colors.BOLD}{assessment.overall_risk_score:.0f}{Colors.RESET} / 100"
        )
        print(
            f"  Grade:       {grade_color}{Colors.BOLD}{grade}{Colors.RESET}"
        )

        if assessment.risk_classification is not None:
            tier = assessment.risk_classification.tier
            tier_color = Colors.RED if tier in ("HIGH", "UNACCEPTABLE") else Colors.YELLOW
            print(f"  EU AI Act:   {tier_color}{tier}{Colors.RESET}")

        if assessment.compliance_scores:
            print(f"\n{Colors.BOLD}  Compliance Scores:{Colors.RESET}")
            for framework, pct in assessment.compliance_scores.items():
                bar_filled = int(pct / 5)
                bar_empty = 20 - bar_filled
                color = Colors.GREEN if pct >= 70 else (Colors.YELLOW if pct >= 40 else Colors.RED)
                print(
                    f"    {framework:20s} {color}{'|' * bar_filled}{Colors.DIM}{'.' * bar_empty}"
                    f"{Colors.RESET} {pct:.0f}%"
                )

        # Documentation findings breakdown
        if assessment.documentation_findings:
            adequate = sum(1 for f in assessment.documentation_findings if f.assessment == "ADEQUATE")
            partial = sum(1 for f in assessment.documentation_findings if f.assessment == "PARTIAL")
            inadequate = sum(1 for f in assessment.documentation_findings if f.assessment == "INADEQUATE")
            total = len(assessment.documentation_findings)
            print(f"\n{Colors.BOLD}  Documentation Audit:{Colors.RESET}")
            print(
                f"    {Colors.GREEN}ADEQUATE: {adequate}{Colors.RESET}  "
                f"{Colors.YELLOW}PARTIAL: {partial}{Colors.RESET}  "
                f"{Colors.RED}INADEQUATE: {inadequate}{Colors.RESET}  "
                f"{Colors.DIM}Total: {total}{Colors.RESET}"
            )

        # Red team summary
        if assessment.red_team_results is not None:
            rt = assessment.red_team_results
            print(f"\n{Colors.BOLD}  Red Team Results:{Colors.RESET}")
            print(f"    Total attacks:        {rt.total_attacks}")
            print(f"    Vulnerabilities found: {Colors.RED}{rt.total_vulnerabilities}{Colors.RESET}")
            print(
                f"    Severity: {Colors.RED}HIGH={rt.high_severity_count}{Colors.RESET}  "
                f"{Colors.YELLOW}MED={rt.medium_severity_count}{Colors.RESET}  "
                f"{Colors.DIM}LOW={rt.low_severity_count}{Colors.RESET}"
            )

        print(f"\n{Colors.BOLD}{'=' * 60}{Colors.RESET}\n")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"{Colors.BOLD}AI Guardian Assessment Engine{Colors.RESET}")
    print(f"{Colors.DIM}Core orchestration module for AI governance assessments.{Colors.RESET}\n")

    # Demo: create an assessment and run a documentation audit with sample responses
    engine = AssessmentEngine()
    assessment = engine.create_assessment(
        organization="Demo Corp",
        system_name="CustomerBot AI",
        description="Customer-facing chatbot powered by GPT-4",
        assessor="Demo Assessor",
        mode="docs",
    )

    # Pre-filled responses for demonstration
    demo_responses = {
        "gov_policy": "Yes, we have a formal documented AI governance policy approved by the board.",
        "risk_assessment": "Yes, we have a systematic process for assessing risks before deployment.",
        "roles_accountability": "Roles are defined but not formally documented in a RACI matrix.",
        "training": "Some team members have received training but it is not regular or annual.",
        "data_governance": "Yes, we have a data governance framework covering quality and lineage.",
        "bias_testing": "We perform bias testing before deployment but not regularly after.",
        "security_testing": "No adversarial or red team testing is performed.",
        "monitoring": "Basic monitoring is in place but no drift detection or continuous alerting.",
        "incident_response": "No AI-specific incident response plan exists.",
        "transparency": "Yes, users are informed via a disclosure notice that they interact with AI.",
        "human_oversight": "Human review is available but not systematically applied to all decisions.",
        "third_party": "Third-party vendors are assessed during procurement but not audited regularly.",
        "documentation": "Model cards and design documentation are maintained and updated.",
        "decommission": "No formal decommissioning procedures exist.",
        "eu_compliance": "Not yet classified under the EU AI Act.",
    }

    assessment = engine.run_documentation_audit(assessment, responses=demo_responses)

    # Show summary
    summary = engine.get_assessment_summary(assessment)
    print(f"\n{Colors.BOLD}Assessment Summary:{Colors.RESET}")
    print(f"  ID:    {summary['assessment_id']}")
    print(f"  Score: {summary['risk_score']:.0f} / 100")
    print(f"  Grade: {summary['grade']}")
