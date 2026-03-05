"""
EU AI Act Risk Tier Classification Module for AI Guardian Toolkit.

Classifies AI systems into EU AI Act risk tiers (Unacceptable, High, Limited,
Minimal) through either an interactive questionnaire or programmatic
profile-based classification.
"""

from dataclasses import dataclass, field
from typing import Dict, List

from ai_frameworks import EU_AI_ACT_RISK_TIERS


# ---------------------------------------------------------------------------
# Terminal Colors
# ---------------------------------------------------------------------------

class Colors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


TIER_COLORS = {
    "UNACCEPTABLE": Colors.RED,
    "HIGH": Colors.RED,
    "LIMITED": Colors.YELLOW,
    "MINIMAL": Colors.GREEN,
}


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class RiskClassification:
    tier: str                          # "UNACCEPTABLE" / "HIGH" / "LIMITED" / "MINIMAL"
    confidence: float                  # 0.0 - 1.0
    reasons: List[str]                 # Why this tier was assigned
    obligations: List[str]             # What is required at this tier
    article_references: List[str]      # EU AI Act articles
    risk_factors: Dict[str, str]       # Individual factor assessments
    recommendations: List[str]         # Actionable recommendations


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class RiskClassifier:
    """Classifies AI systems into EU AI Act risk tiers."""

    CLASSIFICATION_QUESTIONS = [
        {
            "id": "purpose",
            "question": "What is the primary purpose of the AI system?",
            "options": [
                {"label": "Social scoring or behavioral manipulation", "risk": "UNACCEPTABLE", "weight": 10},
                {"label": "Real-time biometric identification in public spaces", "risk": "UNACCEPTABLE", "weight": 10},
                {"label": "Critical infrastructure management (energy, transport, water)", "risk": "HIGH", "weight": 8},
                {"label": "Employment/recruitment decisions", "risk": "HIGH", "weight": 8},
                {"label": "Education access or evaluation", "risk": "HIGH", "weight": 7},
                {"label": "Law enforcement or justice administration", "risk": "HIGH", "weight": 8},
                {"label": "Healthcare diagnosis or treatment", "risk": "HIGH", "weight": 8},
                {"label": "Credit scoring or financial decisions", "risk": "HIGH", "weight": 7},
                {"label": "Chatbot or conversational interface", "risk": "LIMITED", "weight": 3},
                {"label": "Content generation (text, image, video)", "risk": "LIMITED", "weight": 3},
                {"label": "General productivity or internal tools", "risk": "MINIMAL", "weight": 1},
                {"label": "Gaming, entertainment, or non-critical automation", "risk": "MINIMAL", "weight": 1},
            ],
        },
        {
            "id": "users",
            "question": "Who are the primary users or subjects of this AI system?",
            "options": [
                {"label": "General public (including vulnerable populations)", "risk": "HIGH", "weight": 5},
                {"label": "General public (adults only)", "risk": "LIMITED", "weight": 3},
                {"label": "Trained professionals with domain expertise", "risk": "LIMITED", "weight": 2},
                {"label": "Internal employees only", "risk": "MINIMAL", "weight": 1},
            ],
        },
        {
            "id": "autonomy",
            "question": "What level of autonomous decision-making does the system have?",
            "options": [
                {"label": "Fully autonomous decisions affecting people's rights or safety", "risk": "HIGH", "weight": 8},
                {"label": "Semi-autonomous with human override available", "risk": "HIGH", "weight": 5},
                {"label": "Advisory only — human makes all final decisions", "risk": "LIMITED", "weight": 2},
                {"label": "Informational only — provides data, no recommendations", "risk": "MINIMAL", "weight": 1},
            ],
        },
        {
            "id": "data_sensitivity",
            "question": "What type of data does the system process?",
            "options": [
                {"label": "Biometric data (face, voice, fingerprint)", "risk": "HIGH", "weight": 7},
                {"label": "Health or medical data", "risk": "HIGH", "weight": 6},
                {"label": "Financial or credit data", "risk": "HIGH", "weight": 5},
                {"label": "Personal data (PII) — names, addresses, etc.", "risk": "LIMITED", "weight": 3},
                {"label": "Anonymized or aggregated data only", "risk": "MINIMAL", "weight": 1},
                {"label": "Public or non-personal data only", "risk": "MINIMAL", "weight": 1},
            ],
        },
        {
            "id": "safety_impact",
            "question": "Could system failure or malfunction cause physical harm or safety risks?",
            "options": [
                {"label": "Yes — direct risk to life or physical safety", "risk": "HIGH", "weight": 9},
                {"label": "Yes — risk to critical infrastructure or services", "risk": "HIGH", "weight": 7},
                {"label": "Possible — indirect impact on wellbeing", "risk": "LIMITED", "weight": 3},
                {"label": "No — no safety implications", "risk": "MINIMAL", "weight": 1},
            ],
        },
        {
            "id": "transparency",
            "question": "Do users know they are interacting with an AI system?",
            "options": [
                {"label": "No — users are unaware of AI involvement", "risk": "HIGH", "weight": 6},
                {"label": "Partially — some disclosure but not prominent", "risk": "LIMITED", "weight": 3},
                {"label": "Yes — clear disclosure is provided", "risk": "MINIMAL", "weight": 1},
            ],
        },
        {
            "id": "reversibility",
            "question": "Are the system's decisions easily reversible?",
            "options": [
                {"label": "No — decisions are permanent or very difficult to reverse", "risk": "HIGH", "weight": 6},
                {"label": "Partially — can be reversed with significant effort", "risk": "LIMITED", "weight": 3},
                {"label": "Yes — easily reversible with appeal mechanisms", "risk": "MINIMAL", "weight": 1},
            ],
        },
    ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def classify_interactive(self) -> RiskClassification:
        """Run interactive terminal-based questionnaire."""
        print(f"\n{Colors.BOLD}{Colors.CYAN}=== EU AI Act Risk Classification Questionnaire ==={Colors.RESET}\n")
        print(f"{Colors.DIM}Answer each question by entering the number of your selection.{Colors.RESET}\n")

        selections: Dict[str, dict] = {}

        for q in self.CLASSIFICATION_QUESTIONS:
            print(f"{Colors.BOLD}{q['question']}{Colors.RESET}")
            for idx, opt in enumerate(q["options"], start=1):
                print(f"  {Colors.CYAN}{idx}{Colors.RESET}. {opt['label']}")

            choice = self._prompt_choice(len(q["options"]))
            selected = q["options"][choice - 1]
            selections[q["id"]] = selected
            print()

        classification = self._calculate_classification(selections)
        print(self.get_classification_summary(classification))
        return classification

    def classify_from_profile(self, profile: Dict[str, int]) -> RiskClassification:
        """Classify from a pre-filled profile.

        Args:
            profile: Dict mapping question id to selected option index (0-based).
                     Example: {"purpose": 6, "users": 2, "autonomy": 1, ...}
        """
        selections: Dict[str, dict] = {}
        question_map = {q["id"]: q for q in self.CLASSIFICATION_QUESTIONS}

        for qid, option_index in profile.items():
            if qid not in question_map:
                raise ValueError(f"Unknown question id: {qid}")
            options = question_map[qid]["options"]
            if option_index < 0 or option_index >= len(options):
                raise ValueError(
                    f"Option index {option_index} out of range for question '{qid}' "
                    f"(valid: 0-{len(options) - 1})"
                )
            selections[qid] = options[option_index]

        return self._calculate_classification(selections)

    def get_classification_summary(self, classification: RiskClassification) -> str:
        """Return a formatted string summary for terminal display."""
        color = TIER_COLORS.get(classification.tier, Colors.RESET)
        lines = [
            f"\n{Colors.BOLD}{'=' * 60}{Colors.RESET}",
            f"{Colors.BOLD}  EU AI Act Risk Classification Result{Colors.RESET}",
            f"{Colors.BOLD}{'=' * 60}{Colors.RESET}",
            f"",
            f"  Risk Tier:   {color}{Colors.BOLD}{classification.tier}{Colors.RESET}",
            f"  Confidence:  {classification.confidence:.0%}",
            f"",
            f"{Colors.BOLD}  Reasons:{Colors.RESET}",
        ]
        for reason in classification.reasons:
            lines.append(f"    - {reason}")

        lines.append(f"\n{Colors.BOLD}  Obligations:{Colors.RESET}")
        for obligation in classification.obligations:
            lines.append(f"    - {obligation}")

        lines.append(f"\n{Colors.BOLD}  Article References:{Colors.RESET}")
        for ref in classification.article_references:
            lines.append(f"    - {ref}")

        lines.append(f"\n{Colors.BOLD}  Risk Factors:{Colors.RESET}")
        for factor, assessment in classification.risk_factors.items():
            lines.append(f"    {Colors.DIM}{factor}:{Colors.RESET} {assessment}")

        lines.append(f"\n{Colors.BOLD}  Recommendations:{Colors.RESET}")
        for rec in classification.recommendations:
            lines.append(f"    {Colors.CYAN}-{Colors.RESET} {rec}")

        lines.append(f"\n{Colors.BOLD}{'=' * 60}{Colors.RESET}\n")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _calculate_classification(self, selections: Dict[str, dict]) -> RiskClassification:
        """Core classification logic."""
        has_unacceptable = any(s["risk"] == "UNACCEPTABLE" for s in selections.values())
        total_weight = sum(s["weight"] for s in selections.values())

        # Determine tier ------------------------------------------------
        if has_unacceptable:
            tier = "UNACCEPTABLE"
        elif total_weight >= 30:
            tier = "HIGH"
        elif total_weight >= 15:
            tier = "LIMITED"
        else:
            tier = "MINIMAL"

        # Build reasons from highest-weight selections ------------------
        sorted_factors = sorted(selections.items(), key=lambda kv: kv[1]["weight"], reverse=True)
        reasons: List[str] = []
        for qid, sel in sorted_factors:
            if sel["risk"] == "UNACCEPTABLE":
                reasons.append(f"{sel['label']} (triggers UNACCEPTABLE classification)")
            elif sel["weight"] >= 5:
                reasons.append(f"{sel['label']} (risk factor: {sel['risk']}, weight: {sel['weight']})")
        if not reasons:
            reasons.append("All assessed factors indicate low risk.")

        # Risk factors map ----------------------------------------------
        risk_factors: Dict[str, str] = {}
        question_labels = {q["id"]: q["question"] for q in self.CLASSIFICATION_QUESTIONS}
        for qid, sel in selections.items():
            risk_factors[question_labels.get(qid, qid)] = f"{sel['label']} [{sel['risk']}]"

        # Obligations and articles from framework data ------------------
        tier_info = EU_AI_ACT_RISK_TIERS.get(tier, {})
        obligations = list(tier_info.get("requirements", []))
        article_references = list(tier_info.get("articles", []))

        # Confidence score ----------------------------------------------
        confidence = self._compute_confidence(tier, selections)

        # Recommendations -----------------------------------------------
        recommendations = self._generate_recommendations(tier, risk_factors)

        return RiskClassification(
            tier=tier,
            confidence=confidence,
            reasons=reasons,
            obligations=obligations,
            article_references=article_references,
            risk_factors=risk_factors,
            recommendations=recommendations,
        )

    def _compute_confidence(self, tier: str, selections: Dict[str, dict]) -> float:
        """Compute a confidence score based on selection consistency."""
        if tier == "UNACCEPTABLE":
            return 0.99

        tier_counts: Dict[str, int] = {}
        for sel in selections.values():
            tier_counts[sel["risk"]] = tier_counts.get(sel["risk"], 0) + 1

        total = len(selections)
        if total == 0:
            return 0.5

        dominant_count = max(tier_counts.values())
        agreement_ratio = dominant_count / total

        # Scale confidence: perfect agreement -> 0.95, fully mixed -> 0.50
        confidence = 0.50 + 0.45 * agreement_ratio
        return round(min(confidence, 0.99), 2)

    def _generate_recommendations(self, tier: str, risk_factors: Dict) -> List[str]:
        """Generate actionable recommendations based on classification."""
        recommendations: List[str] = []

        if tier == "UNACCEPTABLE":
            recommendations = [
                "STOP: This AI system is prohibited under the EU AI Act.",
                "Consult legal counsel immediately regarding compliance.",
                "Evaluate whether the system can be redesigned to fall below the unacceptable threshold.",
                "Document all risk factors for regulatory records.",
                "Consider alternative non-AI approaches to achieve the same objective.",
            ]
        elif tier == "HIGH":
            recommendations = [
                "Conduct a conformity assessment before market placement (Article 43).",
                "Implement a comprehensive risk management system (Article 9).",
                "Establish data governance and quality management practices (Article 10).",
                "Create and maintain detailed technical documentation (Article 11).",
                "Implement automatic logging and event recording (Article 12).",
                "Design for transparency and provide clear user instructions (Article 13).",
                "Enable meaningful human oversight mechanisms (Article 14).",
                "Ensure accuracy, robustness, and cybersecurity (Article 15).",
                "Register the system in the EU database for high-risk AI systems.",
                "Implement a quality management system (Article 17).",
            ]
        elif tier == "LIMITED":
            recommendations = [
                "Implement transparency notices informing users of AI interaction.",
                "Label any AI-generated or manipulated content clearly.",
                "Provide users with information about the system's capabilities and limitations.",
                "Consider voluntary adherence to high-risk requirements for added trust.",
                "Document the transparency measures in place.",
            ]
        else:  # MINIMAL
            recommendations = [
                "Consider adopting a voluntary code of conduct (Article 95).",
                "Document the AI system's purpose and scope for internal records.",
                "Monitor the regulatory landscape for changes that may affect classification.",
                "Implement basic transparency practices as a best-practice measure.",
            ]

        return recommendations

    @staticmethod
    def _prompt_choice(max_option: int) -> int:
        """Prompt user for a valid numeric choice."""
        while True:
            try:
                raw = input(f"  {Colors.DIM}> Enter choice (1-{max_option}):{Colors.RESET} ")
                choice = int(raw.strip())
                if 1 <= choice <= max_option:
                    return choice
                print(f"  {Colors.RED}Please enter a number between 1 and {max_option}.{Colors.RESET}")
            except ValueError:
                print(f"  {Colors.RED}Invalid input. Please enter a number.{Colors.RESET}")
            except (EOFError, KeyboardInterrupt):
                print(f"\n{Colors.YELLOW}Classification cancelled.{Colors.RESET}")
                raise SystemExit(1)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    classifier = RiskClassifier()
    result = classifier.classify_interactive()
