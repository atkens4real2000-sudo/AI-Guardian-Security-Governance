"""
AI Governance Framework Data for AI Guardian Toolkit.

Static data layer containing structured definitions for:
- NIST AI Risk Management Framework (AI RMF 1.0)
- EU AI Act Risk Tiers
- ISO/IEC 42001 AI Management System Controls
- OWASP Top 10 for LLM Applications 2025
"""

from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# NIST AI RISK MANAGEMENT FRAMEWORK (AI RMF 1.0)
# 4 Functions, 19 Categories, ~72 Subcategories
# ---------------------------------------------------------------------------

NIST_AI_RMF = {
    "GOVERN": {
        "name": "Govern",
        "description": "Cultivate and implement a culture of risk management within organizations designing, developing, deploying, or using AI systems.",
        "categories": {
            "GOVERN-1": {
                "name": "Policies, Processes, Procedures, and Practices",
                "subcategories": {
                    "GOVERN-1.1": {
                        "requirement": "Legal and regulatory requirements involving AI are understood, managed, and documented.",
                        "evidence_examples": ["AI policy document", "Regulatory compliance matrix", "Legal review records", "Board-approved AI governance charter"],
                        "remediation": "Develop and adopt a formal AI governance policy that addresses applicable legal and regulatory requirements."
                    },
                    "GOVERN-1.2": {
                        "requirement": "The characteristics of trustworthy AI are integrated into organizational policies, processes, and procedures.",
                        "evidence_examples": ["Trustworthy AI principles documentation", "Updated process documentation", "Training materials on AI trustworthiness"],
                        "remediation": "Integrate trustworthy AI characteristics (valid, reliable, safe, secure, privacy-enhanced, fair, transparent, accountable) into governance policies."
                    },
                    "GOVERN-1.3": {
                        "requirement": "Processes, procedures, and practices are in place to determine the needed level of risk management activities based on the assessed risk.",
                        "evidence_examples": ["Risk-tiering methodology", "Risk assessment procedures", "Decision framework documentation"],
                        "remediation": "Establish a risk-tiering process that scales governance activities proportionally to AI system risk levels."
                    },
                    "GOVERN-1.4": {
                        "requirement": "The risk management process and its outcomes are established through transparent policies and other controls.",
                        "evidence_examples": ["Published AI risk management policy", "Stakeholder communication records", "Transparency reports"],
                        "remediation": "Create transparent documentation of risk management processes and make them accessible to relevant stakeholders."
                    },
                }
            },
            "GOVERN-2": {
                "name": "Accountability Structures",
                "subcategories": {
                    "GOVERN-2.1": {
                        "requirement": "Roles and responsibilities and lines of communication related to mapping, measuring, and managing AI risks are documented and are clear to individuals and teams.",
                        "evidence_examples": ["RACI matrix for AI governance", "Organizational chart with AI roles", "Role descriptions"],
                        "remediation": "Define and document clear roles, responsibilities, and communication lines for AI risk management."
                    },
                    "GOVERN-2.2": {
                        "requirement": "The organization's personnel and partners receive AI risk management training.",
                        "evidence_examples": ["Training completion records", "Training curriculum", "Partner training agreements"],
                        "remediation": "Implement mandatory AI risk management training for all personnel and partners involved in AI systems."
                    },
                    "GOVERN-2.3": {
                        "requirement": "Executive leadership of the organization takes responsibility for decisions about risks associated with AI system development and deployment.",
                        "evidence_examples": ["Board meeting minutes on AI risk", "Executive risk acceptance documents", "Leadership accountability statements"],
                        "remediation": "Establish executive-level accountability for AI risk decisions with documented sign-off procedures."
                    },
                }
            },
            "GOVERN-3": {
                "name": "Workforce Diversity, Equity, Inclusion, and Accessibility",
                "subcategories": {
                    "GOVERN-3.1": {
                        "requirement": "Decision-making related to mapping, measuring, and managing AI risks throughout the lifecycle is informed by a diverse team.",
                        "evidence_examples": ["Team composition records", "Diversity metrics", "Inclusive hiring practices for AI teams"],
                        "remediation": "Ensure AI governance teams include diverse perspectives across demographics, disciplines, and expertise areas."
                    },
                    "GOVERN-3.2": {
                        "requirement": "Policies and procedures are in place to address AI risks and benefits arising from third-party software and data.",
                        "evidence_examples": ["Third-party AI assessment procedures", "Vendor risk management policy", "Supply chain audit records"],
                        "remediation": "Develop policies for evaluating and managing risks from third-party AI components, data sources, and services."
                    },
                }
            },
            "GOVERN-4": {
                "name": "Organizational Context",
                "subcategories": {
                    "GOVERN-4.1": {
                        "requirement": "Organizational practices are in place to enable AI testing, identification of incidents, and information sharing.",
                        "evidence_examples": ["AI incident response plan", "Testing protocols", "Information sharing agreements"],
                        "remediation": "Establish AI-specific incident response procedures and enable systematic testing and information sharing."
                    },
                    "GOVERN-4.2": {
                        "requirement": "Organizational teams are committed to a culture that considers and communicates AI risk.",
                        "evidence_examples": ["Culture assessment results", "Internal communications on AI risk", "Employee survey data"],
                        "remediation": "Foster an organizational culture that openly discusses and communicates AI-related risks."
                    },
                    "GOVERN-4.3": {
                        "requirement": "Organizational practices are in place to enable AI actors to regularly incorporate adjudicated feedback from relevant AI actors.",
                        "evidence_examples": ["Feedback collection mechanisms", "Feedback incorporation records", "Stakeholder engagement logs"],
                        "remediation": "Implement structured feedback mechanisms for AI stakeholders and ensure feedback is systematically addressed."
                    },
                }
            },
            "GOVERN-5": {
                "name": "Engagement with AI Actors",
                "subcategories": {
                    "GOVERN-5.1": {
                        "requirement": "Organizational policies and practices are in place to collect, consider, prioritize, and integrate feedback from those external to the team.",
                        "evidence_examples": ["External feedback policy", "Community engagement records", "Public comment processes"],
                        "remediation": "Create formal channels for collecting and integrating external stakeholder feedback on AI systems."
                    },
                    "GOVERN-5.2": {
                        "requirement": "Mechanisms are established to enable AI actors to regularly incorporate adjudicated feedback from relevant AI actors in the value chain.",
                        "evidence_examples": ["Value chain feedback agreements", "Cross-organizational review processes", "Partnership feedback protocols"],
                        "remediation": "Establish cross-organizational feedback mechanisms throughout the AI value chain."
                    },
                }
            },
            "GOVERN-6": {
                "name": "Risk Management Integration",
                "subcategories": {
                    "GOVERN-6.1": {
                        "requirement": "Policies and procedures are in place that address AI risks associated with third-party entities.",
                        "evidence_examples": ["Third-party risk policy", "Vendor assessment records", "Contractual AI risk clauses"],
                        "remediation": "Develop comprehensive policies addressing AI risks from third-party entities including vendors, partners, and data providers."
                    },
                    "GOVERN-6.2": {
                        "requirement": "Contingency processes are in place for addressing AI system failures or incidents.",
                        "evidence_examples": ["AI incident response playbooks", "Business continuity plans for AI", "Disaster recovery procedures"],
                        "remediation": "Create AI-specific contingency and incident response plans with defined escalation procedures."
                    },
                }
            },
        }
    },
    "MAP": {
        "name": "Map",
        "description": "Establish context to frame risks related to an AI system. Identify and document AI system purposes, potential impacts, and risks.",
        "categories": {
            "MAP-1": {
                "name": "Context Establishment",
                "subcategories": {
                    "MAP-1.1": {
                        "requirement": "Intended purposes, potentially beneficial uses, context of use, and design assumptions of the AI system are documented.",
                        "evidence_examples": ["System purpose documentation", "Use case specifications", "Design assumption records"],
                        "remediation": "Document the intended purpose, beneficial uses, deployment context, and design assumptions for each AI system."
                    },
                    "MAP-1.2": {
                        "requirement": "Interdisciplinary AI actors, competencies, skills, and capacities for establishing context reflect demographic diversity and domain expertise.",
                        "evidence_examples": ["Team composition documentation", "Skills assessment records", "Domain expert participation logs"],
                        "remediation": "Ensure interdisciplinary and demographically diverse teams participate in AI context establishment."
                    },
                    "MAP-1.3": {
                        "requirement": "The business value or context of business use has been clearly defined or — in the case of assessing existing AI systems — re-evaluated.",
                        "evidence_examples": ["Business case documentation", "Value assessment reports", "ROI analysis for AI systems"],
                        "remediation": "Clearly define and document the business value and context for each AI system deployment."
                    },
                    "MAP-1.4": {
                        "requirement": "The organization's mission and relevant goals for the AI technology are documented.",
                        "evidence_examples": ["AI strategy alignment documentation", "Mission-AI mapping", "Strategic goal documentation"],
                        "remediation": "Document how AI technology aligns with organizational mission and strategic goals."
                    },
                }
            },
            "MAP-2": {
                "name": "AI System Categorization",
                "subcategories": {
                    "MAP-2.1": {
                        "requirement": "The specific tasks and methods used to implement the tasks that the AI system will support are defined.",
                        "evidence_examples": ["Task specification documents", "Method documentation", "Algorithm selection rationale"],
                        "remediation": "Define and document specific tasks, methods, and algorithms used by the AI system."
                    },
                    "MAP-2.2": {
                        "requirement": "Information about the AI system's knowledge limits and how system output may be utilized is documented.",
                        "evidence_examples": ["System limitations documentation", "Output usage guidelines", "Known failure modes"],
                        "remediation": "Document AI system knowledge limits, failure modes, and guidelines for appropriate output usage."
                    },
                    "MAP-2.3": {
                        "requirement": "Scientific integrity and TEVV considerations are identified and documented.",
                        "evidence_examples": ["Scientific validation records", "TEVV plan", "Reproducibility documentation"],
                        "remediation": "Establish and document scientific integrity standards and Test, Evaluation, Verification, and Validation (TEVV) plans."
                    },
                }
            },
            "MAP-3": {
                "name": "Benefits and Costs",
                "subcategories": {
                    "MAP-3.1": {
                        "requirement": "Potential benefits and costs are assessed for AI system stakeholders.",
                        "evidence_examples": ["Stakeholder impact assessment", "Cost-benefit analysis", "Social impact evaluation"],
                        "remediation": "Conduct and document benefit-cost assessments for all identified AI system stakeholders."
                    },
                    "MAP-3.2": {
                        "requirement": "Potential costs including risks of non-deployment of AI systems are considered.",
                        "evidence_examples": ["Non-deployment risk assessment", "Opportunity cost analysis", "Comparative risk evaluation"],
                        "remediation": "Evaluate and document the potential costs and risks associated with not deploying the AI system."
                    },
                    "MAP-3.3": {
                        "requirement": "Targeted application scope is specified and documented based on the system's capability.",
                        "evidence_examples": ["Scope definition document", "Capability boundaries documentation", "Out-of-scope use identification"],
                        "remediation": "Clearly specify and document the targeted application scope and boundaries of the AI system."
                    },
                }
            },
            "MAP-4": {
                "name": "Risk Identification",
                "subcategories": {
                    "MAP-4.1": {
                        "requirement": "Approaches for mapping AI technology and legal risks of its components are in place and documented.",
                        "evidence_examples": ["Technology risk mapping", "Legal risk assessment", "Component risk analysis"],
                        "remediation": "Implement documented approaches for mapping technology and legal risks associated with AI components."
                    },
                    "MAP-4.2": {
                        "requirement": "Internal risk controls for components of the AI system are identified and documented.",
                        "evidence_examples": ["Risk control inventory", "Control effectiveness documentation", "Control testing records"],
                        "remediation": "Identify, document, and test internal risk controls for all AI system components."
                    },
                }
            },
            "MAP-5": {
                "name": "Stakeholder Impact Assessment",
                "subcategories": {
                    "MAP-5.1": {
                        "requirement": "Likelihood and magnitude of each identified impact are determined.",
                        "evidence_examples": ["Impact likelihood assessment", "Magnitude scoring records", "Risk quantification documentation"],
                        "remediation": "Assess and document the likelihood and magnitude of each identified stakeholder impact."
                    },
                    "MAP-5.2": {
                        "requirement": "Practices and personnel for defining, understanding, and documenting AI system impacts are in place.",
                        "evidence_examples": ["Impact assessment procedures", "Personnel assignments", "Impact documentation templates"],
                        "remediation": "Establish defined practices and assign personnel for systematic AI system impact assessment."
                    },
                }
            },
        }
    },
    "MEASURE": {
        "name": "Measure",
        "description": "Employ quantitative, qualitative, or mixed-method tools, techniques, and methodologies to analyze, assess, benchmark, and monitor AI risk and related impacts.",
        "categories": {
            "MEASURE-1": {
                "name": "Risk Metrics and Measurement",
                "subcategories": {
                    "MEASURE-1.1": {
                        "requirement": "Approaches and metrics for measurement of AI risks are selected based on established state-of-the-art or recognized science.",
                        "evidence_examples": ["Metric selection documentation", "Scientific basis references", "Measurement methodology records"],
                        "remediation": "Select and document risk measurement approaches and metrics grounded in established science and industry standards."
                    },
                    "MEASURE-1.2": {
                        "requirement": "Appropriateness of AI metrics and effectiveness of existing measures are regularly assessed and updated.",
                        "evidence_examples": ["Metric review records", "Effectiveness assessment reports", "Updated measurement plans"],
                        "remediation": "Implement regular review cycles to assess and update AI risk metrics and measurement effectiveness."
                    },
                    "MEASURE-1.3": {
                        "requirement": "Internal experts who did not serve as combatants in developing the system provide an assessment of the system.",
                        "evidence_examples": ["Independent review records", "Expert assessment reports", "Conflict of interest disclosures"],
                        "remediation": "Engage internal experts independent of the development team to provide objective system assessments."
                    },
                }
            },
            "MEASURE-2": {
                "name": "AI System Evaluation",
                "subcategories": {
                    "MEASURE-2.1": {
                        "requirement": "AI system performance or assurance criteria are measured qualitatively or quantitatively and demonstrated for conditions including deployment.",
                        "evidence_examples": ["Performance test results", "Assurance criteria benchmarks", "Deployment condition testing"],
                        "remediation": "Establish and execute performance measurement processes for AI systems under realistic deployment conditions."
                    },
                    "MEASURE-2.2": {
                        "requirement": "AI system properties are examined for validity, reliability, robustness, fairness, security, and resilience.",
                        "evidence_examples": ["Trustworthiness evaluation reports", "Bias testing results", "Security assessment findings"],
                        "remediation": "Conduct comprehensive evaluations of AI systems across all trustworthiness dimensions."
                    },
                    "MEASURE-2.3": {
                        "requirement": "AI system performance or assurance criteria are measured qualitatively or quantitatively for deployed systems.",
                        "evidence_examples": ["Production monitoring data", "Post-deployment assessment reports", "Ongoing performance metrics"],
                        "remediation": "Implement continuous performance monitoring and measurement for deployed AI systems."
                    },
                    "MEASURE-2.4": {
                        "requirement": "The functionality and behavior of the AI system and its components are monitored in production.",
                        "evidence_examples": ["Production monitoring dashboards", "Anomaly detection logs", "Behavioral drift reports"],
                        "remediation": "Deploy production monitoring systems that track AI functionality, behavior, and component performance."
                    },
                    "MEASURE-2.5": {
                        "requirement": "The AI system's security and resilience are assessed against adversarial threats.",
                        "evidence_examples": ["Red team assessment results", "Adversarial testing reports", "Penetration test findings"],
                        "remediation": "Conduct regular adversarial security assessments including red teaming and penetration testing of AI systems."
                    },
                    "MEASURE-2.6": {
                        "requirement": "AI system is evaluated regularly for safety risks.",
                        "evidence_examples": ["Safety evaluation reports", "Periodic safety review records", "Hazard analysis documentation"],
                        "remediation": "Implement regular safety evaluations and hazard analyses for AI systems."
                    },
                }
            },
            "MEASURE-3": {
                "name": "Risk Tracking",
                "subcategories": {
                    "MEASURE-3.1": {
                        "requirement": "AI risks and benefits from third-party resources are regularly monitored.",
                        "evidence_examples": ["Third-party monitoring reports", "Vendor risk assessments", "Supply chain audit results"],
                        "remediation": "Establish regular monitoring processes for risks and benefits from third-party AI resources."
                    },
                    "MEASURE-3.2": {
                        "requirement": "Risk tracking approaches are considered for settings where AI risks are difficult to assess using currently available measurement techniques.",
                        "evidence_examples": ["Risk tracking methodology documentation", "Emerging risk assessment approaches", "Measurement gap analysis"],
                        "remediation": "Develop and document risk tracking approaches for AI risks that are difficult to assess with current techniques."
                    },
                    "MEASURE-3.3": {
                        "requirement": "Feedback processes for end users and impacted communities are established.",
                        "evidence_examples": ["User feedback channels", "Community engagement records", "Feedback analysis reports"],
                        "remediation": "Create accessible feedback mechanisms for end users and communities impacted by AI systems."
                    },
                }
            },
            "MEASURE-4": {
                "name": "Feedback Integration",
                "subcategories": {
                    "MEASURE-4.1": {
                        "requirement": "Measurement approaches for identifying AI risks are connected to deployment and monitoring.",
                        "evidence_examples": ["Integrated monitoring architecture", "Risk-deployment connection documentation", "Automated risk detection systems"],
                        "remediation": "Connect risk measurement approaches directly to deployment monitoring and operational feedback loops."
                    },
                    "MEASURE-4.2": {
                        "requirement": "Measurement results regarding AI system trustworthiness are informed by input from domain experts and affected communities.",
                        "evidence_examples": ["Expert review integration records", "Community input incorporation logs", "Participatory assessment documentation"],
                        "remediation": "Integrate domain expert and community input into trustworthiness measurement and assessment processes."
                    },
                }
            },
        }
    },
    "MANAGE": {
        "name": "Manage",
        "description": "Allocate risk resources to mapped and measured risks on a regular basis and as defined by the Govern function.",
        "categories": {
            "MANAGE-1": {
                "name": "Risk Response",
                "subcategories": {
                    "MANAGE-1.1": {
                        "requirement": "A determination is made as to whether the AI system achieves its intended purpose and stated objectives.",
                        "evidence_examples": ["Purpose achievement assessment", "Objective completion metrics", "Fitness-for-purpose evaluation"],
                        "remediation": "Conduct formal evaluations to determine whether AI systems achieve their intended purpose and objectives."
                    },
                    "MANAGE-1.2": {
                        "requirement": "Treatment of documented AI risks is prioritized based on impact, probability, and available resources.",
                        "evidence_examples": ["Risk prioritization matrix", "Resource allocation records", "Treatment priority documentation"],
                        "remediation": "Implement a structured risk prioritization process based on impact, probability, and available resources."
                    },
                    "MANAGE-1.3": {
                        "requirement": "Responses to the AI risks deemed high priority are developed, planned, and documented.",
                        "evidence_examples": ["Risk response plans", "Mitigation strategy documentation", "Response implementation records"],
                        "remediation": "Develop documented response plans for all high-priority AI risks with clear implementation timelines."
                    },
                    "MANAGE-1.4": {
                        "requirement": "Negative residual risks are documented.",
                        "evidence_examples": ["Residual risk register", "Risk acceptance documentation", "Ongoing monitoring plans for residual risks"],
                        "remediation": "Document all negative residual risks with associated monitoring and acceptance criteria."
                    },
                }
            },
            "MANAGE-2": {
                "name": "Risk Treatment",
                "subcategories": {
                    "MANAGE-2.1": {
                        "requirement": "Resources required to manage AI risks are taken into account along with viable non-AI alternatives.",
                        "evidence_examples": ["Resource assessment documentation", "Alternative analysis reports", "Build vs. buy evaluations"],
                        "remediation": "Assess and document resources needed for AI risk management alongside evaluation of non-AI alternatives."
                    },
                    "MANAGE-2.2": {
                        "requirement": "Mechanisms are in place and applied to sustain the value of deployed AI systems.",
                        "evidence_examples": ["Value sustainment plans", "Model retraining schedules", "Performance maintenance records"],
                        "remediation": "Implement mechanisms for sustaining the value and performance of deployed AI systems over time."
                    },
                    "MANAGE-2.3": {
                        "requirement": "Procedures are followed to respond to and recover from AI incidents.",
                        "evidence_examples": ["Incident response records", "Recovery documentation", "Post-incident review reports"],
                        "remediation": "Establish and regularly test AI incident response and recovery procedures."
                    },
                    "MANAGE-2.4": {
                        "requirement": "Mechanisms are in place and applied, and responsibilities are assigned and understood, for superseding, decommissioning, or phasing out AI systems.",
                        "evidence_examples": ["Decommissioning procedures", "Phase-out plans", "Responsibility assignments for system retirement"],
                        "remediation": "Develop and document procedures for superseding, decommissioning, or phasing out AI systems."
                    },
                }
            },
            "MANAGE-3": {
                "name": "Continuous Improvement",
                "subcategories": {
                    "MANAGE-3.1": {
                        "requirement": "AI risks and benefits from third-party resources are regularly monitored, and risk treatments are applied and documented.",
                        "evidence_examples": ["Third-party monitoring reports", "Risk treatment records", "Vendor reassessment documentation"],
                        "remediation": "Implement regular monitoring and documented risk treatment for third-party AI resources."
                    },
                    "MANAGE-3.2": {
                        "requirement": "Pre-defined procedures for system testing, incident identification, and information sharing are followed.",
                        "evidence_examples": ["Testing schedule adherence records", "Incident reporting logs", "Information sharing compliance documentation"],
                        "remediation": "Ensure adherence to pre-defined procedures for AI system testing, incident identification, and information sharing."
                    },
                }
            },
            "MANAGE-4": {
                "name": "Incident Management",
                "subcategories": {
                    "MANAGE-4.1": {
                        "requirement": "Post-deployment AI system monitoring plans are implemented and include mechanisms for capturing and evaluating input from users.",
                        "evidence_examples": ["Monitoring plan documentation", "User feedback capture systems", "Post-deployment evaluation reports"],
                        "remediation": "Implement comprehensive post-deployment monitoring plans with user feedback integration."
                    },
                    "MANAGE-4.2": {
                        "requirement": "Measurable activities for continual improvements are integrated into AI system updates and include regular engagement with interested parties.",
                        "evidence_examples": ["Continuous improvement metrics", "Stakeholder engagement records", "System update documentation"],
                        "remediation": "Integrate measurable continuous improvement activities into AI system update cycles with stakeholder engagement."
                    },
                    "MANAGE-4.3": {
                        "requirement": "Incidents and errors are communicated to relevant AI actors, including affected communities.",
                        "evidence_examples": ["Incident communication records", "Community notification logs", "Transparency report publications"],
                        "remediation": "Establish transparent communication processes for AI incidents and errors to all affected parties."
                    },
                }
            },
        }
    },
}


# ---------------------------------------------------------------------------
# EU AI ACT RISK TIERS
# ---------------------------------------------------------------------------

EU_AI_ACT_RISK_TIERS = {
    "UNACCEPTABLE": {
        "description": "AI systems that pose an unacceptable risk to people's safety, livelihoods, and rights. These are banned within the EU.",
        "examples": [
            "Social scoring systems by governments",
            "Real-time remote biometric identification in public spaces for law enforcement",
            "AI systems that use subliminal, manipulative, or deceptive techniques to distort behavior",
            "AI systems that exploit vulnerabilities of specific groups (age, disability, social/economic situation)",
            "AI systems that infer emotions in workplaces or educational institutions (with exceptions)",
            "Untargeted scraping of facial images from internet or CCTV for facial recognition databases",
        ],
        "requirements": [
            "Prohibited — these systems may not be placed on the market or put into service in the EU",
        ],
        "articles": ["Article 5"],
    },
    "HIGH": {
        "description": "AI systems that create significant risk to health, safety, or fundamental rights. Allowed but subject to strict requirements before market placement.",
        "examples": [
            "Biometric identification and categorization of natural persons",
            "Management and operation of critical infrastructure (water, gas, electricity, transport)",
            "Education and vocational training (determining access, evaluating learning outcomes)",
            "Employment, worker management, and access to self-employment (recruitment, task allocation)",
            "Access to essential private and public services (credit scoring, emergency services)",
            "Law enforcement (individual risk assessment, polygraphs, evidence reliability assessment)",
            "Migration, asylum, and border control management",
            "Administration of justice and democratic processes",
        ],
        "requirements": [
            "Adequate risk assessment and mitigation systems",
            "High quality of datasets feeding the system to minimize discriminatory outcomes",
            "Logging of activity to ensure traceability of results",
            "Detailed documentation providing all necessary information about the system",
            "Clear and adequate information to the deployer",
            "Appropriate human oversight measures to minimize risk",
            "High level of robustness, security, and accuracy",
            "Registration in EU database for high-risk AI systems",
            "Conformity assessment before market placement",
            "Quality management system implementation",
        ],
        "articles": ["Article 6", "Article 8-15", "Article 16-29", "Annex III"],
    },
    "LIMITED": {
        "description": "AI systems with specific transparency obligations. Users must be informed they are interacting with AI.",
        "examples": [
            "Chatbots and conversational AI agents",
            "Emotion recognition systems",
            "Biometric categorization systems",
            "AI systems that generate or manipulate image, audio, or video content (deepfakes)",
        ],
        "requirements": [
            "Transparency obligations — users must be informed they are interacting with AI",
            "Deepfakes must be clearly labeled as artificially generated or manipulated",
            "AI-generated text published to inform the public on matters of public interest must be labeled",
            "Emotion recognition and biometric categorization must inform subjects of system operation",
        ],
        "articles": ["Article 50"],
    },
    "MINIMAL": {
        "description": "AI systems with minimal or no risk. Free use is permitted with no restrictions beyond existing legislation.",
        "examples": [
            "AI-enabled video games",
            "Spam filters",
            "Inventory management systems",
            "AI-powered search engines (general purpose)",
            "AI-enabled manufacturing optimization",
        ],
        "requirements": [
            "No specific requirements beyond existing legislation",
            "Voluntary codes of conduct encouraged",
        ],
        "articles": ["Article 95"],
    },
}


# ---------------------------------------------------------------------------
# ISO/IEC 42001 AI MANAGEMENT SYSTEM CONTROLS (Annex A)
# ---------------------------------------------------------------------------

ISO_42001_CONTROLS = {
    "A.2": {
        "topic": "AI Policy",
        "objectives": {
            "A.2.2": {
                "objective": "AI policy — establish an AI policy appropriate to the organization's purpose.",
                "guidance": "The AI policy should address the organization's commitment to responsible AI, alignment with organizational values, and compliance with applicable requirements.",
                "evidence_examples": ["Approved AI policy document", "Policy review records", "Distribution and acknowledgment logs"],
            },
            "A.2.3": {
                "objective": "AI system impact assessment policy — establish a policy for assessing the impacts of AI systems.",
                "guidance": "Define when and how AI impact assessments are triggered, conducted, and reviewed.",
                "evidence_examples": ["Impact assessment policy", "Assessment trigger criteria", "Review cycle documentation"],
            },
            "A.2.4": {
                "objective": "Objectives for responsible use of AI — establish measurable objectives aligned with the AI policy.",
                "guidance": "Set quantifiable targets for responsible AI use, including fairness metrics, transparency goals, and safety thresholds.",
                "evidence_examples": ["Measurable AI objectives document", "KPI definitions", "Progress tracking reports"],
            },
        }
    },
    "A.3": {
        "topic": "Internal Organization",
        "objectives": {
            "A.3.2": {
                "objective": "Roles and responsibilities — define and assign roles for AI system lifecycle management.",
                "guidance": "Clearly assign responsibilities for AI governance, development, deployment, monitoring, and incident response.",
                "evidence_examples": ["RACI matrix", "Job descriptions with AI responsibilities", "Organizational structure documentation"],
            },
            "A.3.3": {
                "objective": "Reporting AI system concerns — establish mechanisms for reporting AI-related concerns.",
                "guidance": "Create accessible channels for internal and external stakeholders to report AI concerns without fear of retaliation.",
                "evidence_examples": ["Concern reporting mechanism", "Whistleblower protection policy", "Concern resolution records"],
            },
            "A.3.4": {
                "objective": "Allocation of resources — ensure adequate resources for AI management.",
                "guidance": "Allocate sufficient human, financial, and technical resources for responsible AI development and oversight.",
                "evidence_examples": ["Resource allocation records", "Budget documentation", "Staffing plans"],
            },
        }
    },
    "A.4": {
        "topic": "Resources for AI Systems",
        "objectives": {
            "A.4.2": {
                "objective": "Data resources — manage data used in AI systems throughout its lifecycle.",
                "guidance": "Ensure data quality, provenance, representativeness, and compliance with data protection requirements.",
                "evidence_examples": ["Data management procedures", "Data quality reports", "Data provenance documentation"],
            },
            "A.4.3": {
                "objective": "Tools and frameworks — manage tooling and frameworks used for AI development.",
                "guidance": "Maintain an inventory of AI development tools and ensure they meet security and quality standards.",
                "evidence_examples": ["Tool inventory", "Framework assessment records", "Version control documentation"],
            },
            "A.4.4": {
                "objective": "System and computing resources — ensure adequate computing infrastructure.",
                "guidance": "Provision and maintain computing resources sufficient for AI system development, testing, and deployment.",
                "evidence_examples": ["Infrastructure documentation", "Capacity planning records", "Resource monitoring reports"],
            },
            "A.4.5": {
                "objective": "Human resources — ensure personnel competency for AI systems.",
                "guidance": "Define competency requirements, provide training, and maintain records of AI-related skills development.",
                "evidence_examples": ["Competency framework", "Training records", "Certification documentation"],
            },
        }
    },
    "A.5": {
        "topic": "Assessing Impacts of AI Systems",
        "objectives": {
            "A.5.2": {
                "objective": "AI system impact assessment — conduct assessments of AI system impacts on individuals and society.",
                "guidance": "Systematically evaluate potential negative impacts including bias, discrimination, privacy violations, safety risks, and societal effects.",
                "evidence_examples": ["Impact assessment reports", "Risk ratings", "Stakeholder consultation records"],
            },
            "A.5.3": {
                "objective": "Documenting the AI system impact assessment — maintain records of impact assessments.",
                "guidance": "Document methodology, findings, decisions, and actions taken in response to impact assessments.",
                "evidence_examples": ["Assessment methodology documentation", "Findings register", "Action tracking records"],
            },
            "A.5.4": {
                "objective": "Addressing impacts across the AI system lifecycle — manage impacts throughout development, deployment, and retirement.",
                "guidance": "Implement controls to address identified impacts at each lifecycle stage and monitor their effectiveness.",
                "evidence_examples": ["Lifecycle impact management plan", "Control effectiveness reports", "Stage gate review records"],
            },
        }
    },
    "A.6": {
        "topic": "AI System Lifecycle",
        "objectives": {
            "A.6.2": {
                "objective": "Managing AI system development and acquisition — control AI system development processes.",
                "guidance": "Establish development standards, review processes, and quality gates for AI system creation and acquisition.",
                "evidence_examples": ["Development standards", "Code review records", "Quality gate documentation"],
            },
            "A.6.3": {
                "objective": "Verification and validation — ensure AI systems meet specified requirements.",
                "guidance": "Conduct systematic testing, validation against requirements, and verification of AI system behavior.",
                "evidence_examples": ["Test plans and results", "Validation reports", "Acceptance criteria documentation"],
            },
            "A.6.4": {
                "objective": "Deployment and operation — manage the transition to production and ongoing operation.",
                "guidance": "Define deployment procedures, operational monitoring, and maintenance processes for AI systems.",
                "evidence_examples": ["Deployment procedures", "Operational monitoring dashboards", "Maintenance schedules"],
            },
            "A.6.5": {
                "objective": "Retirement and discontinuation — manage the end-of-life of AI systems.",
                "guidance": "Plan for orderly decommissioning including data handling, stakeholder notification, and transition support.",
                "evidence_examples": ["Retirement plan", "Data disposition records", "Stakeholder notification logs"],
            },
            "A.6.6": {
                "objective": "AI system documentation — maintain comprehensive documentation throughout the lifecycle.",
                "guidance": "Document design decisions, training data, model parameters, performance metrics, and operational procedures.",
                "evidence_examples": ["System documentation repository", "Model cards", "Technical specification documents"],
            },
        }
    },
    "A.7": {
        "topic": "Data for AI Systems",
        "objectives": {
            "A.7.2": {
                "objective": "Data management for AI — establish processes for managing data used in AI systems.",
                "guidance": "Implement data governance covering collection, labeling, storage, processing, and retention of AI training and operational data.",
                "evidence_examples": ["Data governance framework", "Data pipeline documentation", "Data quality metrics"],
            },
            "A.7.3": {
                "objective": "Data quality — ensure data used in AI systems is fit for purpose.",
                "guidance": "Define data quality standards, implement quality checks, and remediate data quality issues.",
                "evidence_examples": ["Data quality standards", "Quality assessment reports", "Remediation records"],
            },
            "A.7.4": {
                "objective": "Data provenance — maintain records of data origin and transformations.",
                "guidance": "Track data lineage from source through all transformations to usage in AI systems.",
                "evidence_examples": ["Data lineage documentation", "Transformation logs", "Source attribution records"],
            },
            "A.7.5": {
                "objective": "Preparing data — ensure proper data preparation for AI system use.",
                "guidance": "Document and control data preprocessing, feature engineering, and data splitting procedures.",
                "evidence_examples": ["Data preparation procedures", "Feature engineering documentation", "Data split rationale"],
            },
        }
    },
    "A.8": {
        "topic": "Information for Interested Parties",
        "objectives": {
            "A.8.2": {
                "objective": "Transparency — provide appropriate transparency about AI system operation to stakeholders.",
                "guidance": "Communicate how AI systems work, their limitations, and their role in decision-making to affected parties.",
                "evidence_examples": ["Transparency reports", "User-facing explanations", "System operation documentation"],
            },
            "A.8.3": {
                "objective": "Provision of information about AI system interaction — inform users when they interact with AI.",
                "guidance": "Clearly indicate when users are interacting with AI systems and provide relevant information about the interaction.",
                "evidence_examples": ["AI interaction notices", "User interface labels", "Disclosure documentation"],
            },
            "A.8.4": {
                "objective": "Communication with interested parties — maintain open communication channels.",
                "guidance": "Establish and maintain communication channels for stakeholders to inquire about or provide feedback on AI systems.",
                "evidence_examples": ["Communication channel documentation", "Inquiry response records", "Stakeholder feedback logs"],
            },
        }
    },
    "A.9": {
        "topic": "Use of AI Systems",
        "objectives": {
            "A.9.2": {
                "objective": "Intended use — define and communicate the intended use of AI systems.",
                "guidance": "Clearly specify intended use cases, acceptable use boundaries, and prohibited uses for each AI system.",
                "evidence_examples": ["Intended use documentation", "Acceptable use policy", "Prohibited use guidelines"],
            },
            "A.9.3": {
                "objective": "Monitoring of AI systems during use — continuously monitor AI systems in operation.",
                "guidance": "Implement monitoring for performance degradation, bias drift, security threats, and unexpected behaviors.",
                "evidence_examples": ["Monitoring dashboards", "Alert configuration records", "Drift detection reports"],
            },
            "A.9.4": {
                "objective": "Human oversight — ensure appropriate human oversight of AI systems.",
                "guidance": "Define and implement human oversight mechanisms proportional to the risk and impact of AI system decisions.",
                "evidence_examples": ["Human oversight procedures", "Escalation protocols", "Override capability documentation"],
            },
        }
    },
    "A.10": {
        "topic": "Third-Party and Customer Relationships",
        "objectives": {
            "A.10.2": {
                "objective": "Suppliers — manage AI-related risks from suppliers.",
                "guidance": "Assess and manage risks from AI component suppliers, including data providers, model providers, and platform providers.",
                "evidence_examples": ["Supplier assessment records", "Contractual AI requirements", "Supplier audit reports"],
            },
            "A.10.3": {
                "objective": "Customers — address AI responsibilities toward customers.",
                "guidance": "Provide customers with information about AI system capabilities, limitations, and appropriate use.",
                "evidence_examples": ["Customer documentation", "Service level agreements with AI provisions", "Customer support records"],
            },
            "A.10.4": {
                "objective": "Interested parties notification — notify relevant parties about significant AI system changes.",
                "guidance": "Establish notification procedures for material changes to AI systems that affect stakeholders.",
                "evidence_examples": ["Change notification procedures", "Notification records", "Stakeholder acknowledgment logs"],
            },
        }
    },
}


# ---------------------------------------------------------------------------
# OWASP TOP 10 FOR LLM APPLICATIONS 2025
# ---------------------------------------------------------------------------

OWASP_LLM_TOP_10 = {
    "LLM01": {
        "name": "Prompt Injection",
        "description": "Prompt injection occurs when user inputs alter the LLM's behavior in unintended ways. Direct injections overwrite system prompts, while indirect injections manipulate inputs from external sources.",
        "attack_vectors": [
            "Direct prompt injection via crafted user input that overrides system instructions",
            "Indirect prompt injection through poisoned external data sources (web pages, documents, emails)",
            "Multi-turn conversation manipulation to gradually shift LLM behavior",
            "Encoding-based attacks using base64, Unicode, or other encodings to bypass filters",
            "Few-shot prompt manipulation to establish malicious behavioral patterns",
        ],
        "impact": "Unauthorized actions, data exfiltration, social engineering amplification, full system compromise through downstream tool access.",
        "mitigations": [
            "Enforce privilege control on LLM access to backend systems",
            "Add human-in-the-loop for privileged operations",
            "Segregate external content from user prompts",
            "Establish trust boundaries between the LLM, external sources, and extensible functionality",
            "Monitor LLM input and output for anomalous patterns",
            "Implement input validation and sanitization",
        ],
        "severity": "HIGH",
    },
    "LLM02": {
        "name": "Sensitive Information Disclosure",
        "description": "LLMs may reveal sensitive information including PII, proprietary algorithms, system prompts, or confidential business data through their responses.",
        "attack_vectors": [
            "Crafted prompts designed to extract system prompt contents",
            "Training data extraction through memorization probing",
            "Social engineering to elicit confidential information",
            "Side-channel attacks through output analysis and token probabilities",
            "Role-play scenarios to bypass information access controls",
        ],
        "impact": "Exposure of PII, intellectual property theft, system prompt leakage enabling further attacks, regulatory compliance violations.",
        "mitigations": [
            "Integrate adequate data sanitization and scrubbing techniques",
            "Implement robust input validation and sanitization methods",
            "Apply the principle of least privilege for data access",
            "Implement access controls for external data sources",
            "Use differential privacy techniques for training data",
            "Regularly audit LLM outputs for sensitive information leakage",
        ],
        "severity": "HIGH",
    },
    "LLM03": {
        "name": "Supply Chain Vulnerabilities",
        "description": "The AI supply chain can be compromised through vulnerable pre-trained models, poisoned training data, outdated dependencies, or compromised model marketplaces.",
        "attack_vectors": [
            "Use of vulnerable or outdated third-party model components",
            "Compromised pre-trained models from untrusted sources",
            "Poisoned training data from third-party data providers",
            "Outdated or vulnerable software dependencies in the ML pipeline",
        ],
        "impact": "Model compromise, data poisoning, supply chain attacks propagating through downstream applications, intellectual property theft.",
        "mitigations": [
            "Vet data sources and suppliers including terms and conditions and privacy policies",
            "Only use reputable model repositories and verify model integrity with checksums",
            "Use vulnerability scanning and anomaly detection for third-party components",
            "Implement robust monitoring for AI component behaviors and outputs",
            "Maintain an up-to-date software bill of materials (SBOM)",
        ],
        "severity": "MEDIUM",
    },
    "LLM04": {
        "name": "Data and Model Poisoning",
        "description": "Training data manipulation can introduce vulnerabilities, backdoors, or biases into AI models. This includes poisoning pre-training data, fine-tuning data, or embedding data.",
        "attack_vectors": [
            "Training data poisoning through malicious samples in training datasets",
            "Fine-tuning data manipulation to alter model behavior",
            "Embedding poisoning to influence retrieval-augmented generation",
            "Backdoor injection through carefully crafted trigger patterns",
        ],
        "impact": "Model degradation, biased outputs, backdoor access, manipulation of downstream decisions, reputational damage.",
        "mitigations": [
            "Verify the supply chain of training data and maintain provenance documentation",
            "Implement data validation and anomaly detection for training pipelines",
            "Use sandboxed environments for model training and fine-tuning",
            "Monitor model behavior for unexpected changes after updates",
            "Apply adversarial robustness techniques during training",
        ],
        "severity": "MEDIUM",
    },
    "LLM05": {
        "name": "Improper Output Handling",
        "description": "When LLM output is passed to downstream systems without proper validation, it can lead to XSS, SSRF, privilege escalation, or remote code execution.",
        "attack_vectors": [
            "XSS through LLM-generated content rendered in web applications",
            "Server-side request forgery via LLM-generated URLs or API calls",
            "SQL injection through LLM-generated database queries",
            "Command injection via LLM output passed to system shells",
            "Path traversal through LLM-generated file paths",
        ],
        "impact": "Cross-site scripting, server compromise, data exfiltration, remote code execution, privilege escalation in connected systems.",
        "mitigations": [
            "Treat the model as any other user and apply proper input validation to responses",
            "Encode output before rendering in web contexts",
            "Use parameterized queries for any database operations involving LLM output",
            "Implement output filtering and sanitization pipelines",
            "Apply the principle of least privilege to LLM access to downstream systems",
        ],
        "severity": "HIGH",
    },
    "LLM06": {
        "name": "Excessive Agency",
        "description": "LLM-based systems may undertake actions leading to unintended consequences when granted excessive functionality, permissions, or autonomy.",
        "attack_vectors": [
            "Excessive function access allowing the LLM to call unnecessary tools or APIs",
            "Excessive permissions granting the LLM more access than needed for its task",
            "Excessive autonomy allowing the LLM to take high-impact actions without human approval",
            "Tool misuse through prompt manipulation to abuse connected services",
            "Chain-of-action exploitation across multiple connected tools",
        ],
        "impact": "Unauthorized actions on behalf of users, data modification or deletion, financial transactions, privacy breaches, system compromise.",
        "mitigations": [
            "Limit the plugins/tools the LLM is allowed to call to only the minimum necessary",
            "Limit the functions implemented in LLM plugins/tools to the minimum necessary",
            "Avoid open-ended functions and use granular, specific functionality",
            "Require human approval for high-impact actions",
            "Implement rate limiting and monitoring for tool usage",
            "Log all tool invocations for audit purposes",
        ],
        "severity": "HIGH",
    },
    "LLM07": {
        "name": "System Prompt Leakage",
        "description": "System prompts may contain sensitive information including behavioral guidelines, API keys, database schemas, or role-based access control instructions that should remain confidential.",
        "attack_vectors": [
            "Direct requests for system prompt disclosure",
            "Prompt extraction through role-play or debugging scenarios",
            "Behavioral analysis to infer system prompt contents",
            "Error message exploitation to reveal configuration details",
            "Multi-turn extraction using incremental information gathering",
        ],
        "impact": "Exposure of business logic, security bypass through understanding system constraints, intellectual property theft, enabling targeted attacks.",
        "mitigations": [
            "Separate sensitive operational data from system prompts",
            "Implement output filtering to detect and block system prompt content in responses",
            "Do not rely on system prompts for security controls",
            "Use external guardrail systems independent of the LLM",
            "Regularly test for system prompt leakage through red teaming",
        ],
        "severity": "MEDIUM",
    },
    "LLM08": {
        "name": "Vector and Embedding Weaknesses",
        "description": "Vulnerabilities in how vectors and embeddings are generated, stored, or retrieved can be exploited to inject malicious content or manipulate RAG system behavior.",
        "attack_vectors": [
            "Knowledge base poisoning by injecting malicious documents into the vector store",
            "Embedding manipulation to alter semantic similarity calculations",
            "Access control bypass in vector databases to access unauthorized documents",
        ],
        "impact": "Retrieval of manipulated or malicious context, spreading misinformation, unauthorized data access through embedding similarity exploits.",
        "mitigations": [
            "Implement access controls and authentication for vector databases",
            "Validate and sanitize documents before embedding",
            "Monitor for unusual retrieval patterns or embedding anomalies",
            "Use content integrity verification for stored embeddings",
        ],
        "severity": "MEDIUM",
    },
    "LLM09": {
        "name": "Misinformation",
        "description": "LLMs can generate authoritative-sounding but factually incorrect content (hallucinations), which can lead to security vulnerabilities, reputational damage, and legal liability.",
        "attack_vectors": [
            "Deliberate hallucination induction through misleading prompts",
            "Exploitation of knowledge gaps in the model's training data",
            "Authority impersonation to lend credibility to false outputs",
            "Plausible-sounding code generation with subtle security vulnerabilities",
            "Statistical or citation fabrication that appears credible",
        ],
        "impact": "Spreading false information, security vulnerabilities from hallucinated code, legal liability, reputational damage, misguided decision-making.",
        "mitigations": [
            "Implement retrieval-augmented generation (RAG) with verified sources",
            "Use cross-reference verification and fact-checking for critical outputs",
            "Implement confidence scoring and uncertainty indicators",
            "Establish human review processes for high-stakes outputs",
            "Clearly communicate AI system limitations to end users",
        ],
        "severity": "MEDIUM",
    },
    "LLM10": {
        "name": "Unbounded Consumption",
        "description": "LLMs are vulnerable to denial-of-service through resource-exhaustive inputs, excessive API calls, or attacks designed to maximize computational cost.",
        "attack_vectors": [
            "Variable-length input flooding to maximize processing time and cost",
            "Recursive or repetitive prompt patterns causing excessive token generation",
            "Denial-of-wallet attacks designed to exhaust API budgets",
            "Context window stuffing to maximize per-request resource usage",
            "Multi-turn session exhaustion through automated conversation chains",
        ],
        "impact": "Service degradation, excessive costs, denial of service to legitimate users, resource exhaustion in shared environments.",
        "mitigations": [
            "Implement input length validation and limits",
            "Set per-user and per-session rate limits",
            "Implement budget caps and usage monitoring with alerts",
            "Set maximum token limits for both input and output",
            "Implement resource monitoring and auto-scaling protections",
            "Use queue management for request processing",
        ],
        "severity": "MEDIUM",
    },
}


# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def get_all_nist_subcategories() -> List[Dict]:
    """Returns flat list of all NIST AI RMF subcategories with parent info."""
    results = []
    for func_id, func_data in NIST_AI_RMF.items():
        for cat_id, cat_data in func_data["categories"].items():
            for sub_id, sub_data in cat_data["subcategories"].items():
                results.append({
                    "function": func_id,
                    "function_name": func_data["name"],
                    "category_id": cat_id,
                    "category_name": cat_data["name"],
                    "subcategory_id": sub_id,
                    **sub_data,
                })
    return results


def get_nist_category(category_id: str) -> Optional[Dict]:
    """Lookup a specific NIST category by ID (e.g., 'GOVERN-1')."""
    func_prefix = category_id.split("-")[0]
    if func_prefix in NIST_AI_RMF:
        cats = NIST_AI_RMF[func_prefix]["categories"]
        return cats.get(category_id)
    return None


def get_eu_tier_info(tier: str) -> Optional[Dict]:
    """Get EU AI Act info for a risk tier."""
    return EU_AI_ACT_RISK_TIERS.get(tier.upper())


def get_iso_control(control_id: str) -> Optional[Dict]:
    """Lookup ISO 42001 control by ID (e.g., 'A.6')."""
    return ISO_42001_CONTROLS.get(control_id)


def get_owasp_item(item_id: str) -> Optional[Dict]:
    """Lookup OWASP item by ID (e.g., 'LLM01')."""
    return OWASP_LLM_TOP_10.get(item_id.upper())


def get_framework_summary() -> Dict:
    """Returns summary counts for all frameworks."""
    nist_subs = get_all_nist_subcategories()
    nist_cats = sum(len(f["categories"]) for f in NIST_AI_RMF.values())
    iso_objectives = sum(len(c["objectives"]) for c in ISO_42001_CONTROLS.values())

    return {
        "nist_ai_rmf": {
            "functions": len(NIST_AI_RMF),
            "categories": nist_cats,
            "subcategories": len(nist_subs),
        },
        "eu_ai_act": {
            "risk_tiers": len(EU_AI_ACT_RISK_TIERS),
        },
        "iso_42001": {
            "control_topics": len(ISO_42001_CONTROLS),
            "control_objectives": iso_objectives,
        },
        "owasp_llm_top_10": {
            "items": len(OWASP_LLM_TOP_10),
        },
    }
