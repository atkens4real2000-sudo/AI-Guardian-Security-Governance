#!/usr/bin/env python3
"""
AI Guardian - AI Security & Governance Assessment Toolkit (CLI Entry Point).

Provides both command-line argument parsing and an interactive menu for
running AI security assessments, red team tests, risk classification,
governance audits, and report generation.

Equivalent to cmmc_assessor.py in the CMMC Gap Assessment Toolkit.

Usage:
    # Interactive menu
    python guardian.py

    # CLI - new documentation audit
    python guardian.py --new "ChatBot v3" --org "Acme Corp" --docs

    # CLI - live assessment against OpenAI
    python guardian.py --new "ChatBot v3" --org "Acme" --live \
        --provider openai --api-key sk-... --model gpt-4o-mini

    # CLI - generate reports from saved assessment
    python guardian.py --report guardian_reports/assessment_abc123.json

Author: Akintade Akinokun
"""

import argparse
import os
import sys
import traceback

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
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"


# ---------------------------------------------------------------------------
# Module Import Status Tracking
# ---------------------------------------------------------------------------

_MODULE_STATUS = {}


def _try_import(module_name):
    """Attempt to import a module and record its status."""
    try:
        __import__(module_name)
        _MODULE_STATUS[module_name] = True
        return True
    except ImportError:
        _MODULE_STATUS[module_name] = False
        return False


# Probe all sibling modules
_REQUIRED_MODULES = [
    "ai_frameworks",
    "llm_connectors",
    "red_team_engine",
    "risk_classifier",
    "governance_mapper",
    "assessment_engine",
    "report_generators",
    "red_team_console",
]

for _mod in _REQUIRED_MODULES:
    _try_import(_mod)

# Conditional imports -- guarded so the CLI can still show helpful errors
# even if a module is missing.
try:
    from assessment_engine import AssessmentEngine, GuardianAssessment
except ImportError:
    AssessmentEngine = None  # type: ignore[misc, assignment]
    GuardianAssessment = None  # type: ignore[misc, assignment]

try:
    from risk_classifier import RiskClassifier
except ImportError:
    RiskClassifier = None  # type: ignore[misc, assignment]

try:
    from llm_connectors import create_connector, check_available_providers
except ImportError:
    create_connector = None  # type: ignore[misc, assignment]
    check_available_providers = None  # type: ignore[misc, assignment]

try:
    from report_generators import generate_all_reports
except ImportError:
    generate_all_reports = None  # type: ignore[misc, assignment]


# ---------------------------------------------------------------------------
# ASCII Art Banner
# ---------------------------------------------------------------------------

BANNER = r"""
    _    ___    ____                     _ _
   / \  |_ _|  / ___|_   _  __ _ _ __ __| (_) __ _ _ __
  / _ \  | |  | |  _| | | |/ _` | '__/ _` | |/ _` | '_ \
 / ___ \ | |  | |_| | |_| | (_| | | | (_| | | (_| | | | |
/_/   \_\___|  \____|\__,_|\__,_|_|  \__,_|_|\__,_|_| |_|
"""


def print_banner():
    """Print the ASCII art banner with module status check."""
    print(f"{Colors.BOLD}{Colors.CYAN}{BANNER}{Colors.RESET}")
    print(f"{Colors.DIM}  AI Security & Governance Assessment Toolkit{Colors.RESET}")
    print(f"{Colors.DIM}  Author: Akintade Akinokun{Colors.RESET}")
    print()
    _print_module_status()
    print()


def _print_module_status():
    """Print import status for all required modules."""
    print(f"  {Colors.BOLD}Module Status:{Colors.RESET}")
    for module_name in _REQUIRED_MODULES:
        available = _MODULE_STATUS.get(module_name, False)
        if available:
            status_text = f"{Colors.GREEN}OK{Colors.RESET}"
        else:
            status_text = f"{Colors.RED}MISSING{Colors.RESET}"
        # Align module names to 20 chars for neat columns
        padded = f"{module_name}:".ljust(20)
        print(f"    {padded} {status_text}")


# ---------------------------------------------------------------------------
# Argparse Setup
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(
    description="AI Guardian - AI Security & Governance Assessment Toolkit",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=(
        "Examples:\n"
        "  python guardian.py                                   # Interactive menu\n"
        "  python guardian.py --new 'ChatBot' --org 'Acme' --docs\n"
        "  python guardian.py --new 'ChatBot' --live --provider openai --api-key sk-...\n"
        "  python guardian.py --report assessment_abc.json\n"
    ),
)

# Assessment targets
parser.add_argument("--new", metavar="SYSTEM_NAME", help="Start new assessment")
parser.add_argument("--org", metavar="ORG_NAME", default="", help="Organization name")
parser.add_argument("--load", metavar="FILE", help="Load saved assessment from JSON")
parser.add_argument("--report", metavar="FILE", help="Generate reports from saved assessment")
parser.add_argument("--summary", action="store_true", help="Display assessment summary")

# Assessment mode
parser.add_argument("--live", action="store_true", help="Live API testing mode")
parser.add_argument("--docs", action="store_true", help="Documentation audit mode")
parser.add_argument("--agent", action="store_true", help="Agent testing mode")

# Provider configuration
parser.add_argument(
    "--provider",
    choices=["openai", "anthropic", "ollama", "custom"],
    default="openai",
    help="LLM provider for live/agent assessments (default: openai)",
)
parser.add_argument("--api-key", metavar="KEY", help="API key for LLM provider")
parser.add_argument("--model", metavar="MODEL", help="Model name (e.g., gpt-4o-mini)")
parser.add_argument("--endpoint", metavar="URL", help="Custom endpoint URL")

# Options
parser.add_argument(
    "--attacks",
    default="all",
    help="Attack categories: all, injection, leakage, jailbreak, agency, output",
)
parser.add_argument("--system-prompt", metavar="TEXT", help="System prompt to test for leakage")
parser.add_argument("--output-dir", default="./guardian_reports", help="Output directory for reports")
parser.add_argument("--assessor", default="AI Guardian", help="Assessor name")


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _check_engine_available():
    """Verify the AssessmentEngine is importable. Exit with helpful message if not."""
    if AssessmentEngine is None:
        print(f"\n  {Colors.RED}[!] AssessmentEngine could not be imported.{Colors.RESET}")
        print(f"  {Colors.DIM}    Check that assessment_engine.py and its dependencies exist.{Colors.RESET}")
        _print_module_status()
        sys.exit(1)


def _check_reports_available():
    """Verify report generator is importable."""
    if generate_all_reports is None:
        print(f"\n  {Colors.RED}[!] report_generators module could not be imported.{Colors.RESET}")
        print(f"  {Colors.DIM}    Check that report_generators.py and its dependencies exist.{Colors.RESET}")
        sys.exit(1)


def _check_connectors_available():
    """Verify LLM connector factory is importable."""
    if create_connector is None:
        print(f"\n  {Colors.RED}[!] llm_connectors module could not be imported.{Colors.RESET}")
        print(f"  {Colors.DIM}    Check that llm_connectors.py and its dependencies exist.{Colors.RESET}")
        sys.exit(1)


def _check_classifier_available():
    """Verify RiskClassifier is importable."""
    if RiskClassifier is None:
        print(f"\n  {Colors.RED}[!] risk_classifier module could not be imported.{Colors.RESET}")
        print(f"  {Colors.DIM}    Check that risk_classifier.py and its dependencies exist.{Colors.RESET}")
        sys.exit(1)


def _build_connector(args):
    """Build an LLM connector from CLI args."""
    _check_connectors_available()
    kwargs = {}
    if args.api_key:
        kwargs["api_key"] = args.api_key
    if args.model:
        kwargs["model"] = args.model
    if args.endpoint:
        kwargs["endpoint"] = args.endpoint
    return create_connector(args.provider, **kwargs)


def _parse_attack_categories(attacks_str):
    """Parse --attacks flag into a list of OWASP LLM Top 10 category IDs.

    Returns None when all categories should be run.
    """
    if attacks_str == "all":
        return None  # Engine runs full suite when categories is None

    mapping = {
        "injection": ["LLM01"],
        "leakage": ["LLM02", "LLM07"],
        "jailbreak": ["LLM01"],
        "agency": ["LLM06"],
        "output": ["LLM05"],
    }
    categories = mapping.get(attacks_str)
    if categories is None:
        print(
            f"  {Colors.YELLOW}[!] Unknown attack category '{attacks_str}', "
            f"running all categories.{Colors.RESET}"
        )
    return categories


def _save_assessment(engine, assessment, output_dir):
    """Save assessment JSON to *output_dir* and return the file path."""
    os.makedirs(output_dir, exist_ok=True)
    filename = f"assessment_{assessment.assessment_id}.json"
    path = os.path.join(output_dir, filename)
    engine.export_assessment(assessment, path)
    print(f"\n  {Colors.GREEN}[+]{Colors.RESET} Assessment saved to {Colors.BOLD}{path}{Colors.RESET}")
    return path


def _post_assessment(engine, assessment, output_dir):
    """Post-assessment workflow: print summary, save, and generate reports."""
    _check_reports_available()

    # 1. Print score summary
    print_summary(engine, assessment)

    # 2. Save assessment
    save_path = _save_assessment(engine, assessment, output_dir)

    # 3. Generate reports
    data = assessment.to_dict()
    paths = generate_all_reports(data, output_dir)
    print_report_paths(paths)

    return save_path


def print_report_paths(paths):
    """Print a formatted list of generated report file paths."""
    print(f"\n  {Colors.BOLD}Generated Reports:{Colors.RESET}")
    if not paths:
        print(f"    {Colors.DIM}(no reports generated){Colors.RESET}")
        return
    for fmt, path in paths.items():
        print(f"    {Colors.GREEN}[+]{Colors.RESET} {fmt}: {Colors.BOLD}{path}{Colors.RESET}")
    print()


def print_summary(engine, assessment):
    """Print assessment summary dashboard."""
    try:
        engine._print_score_summary(assessment)
    except Exception as exc:
        print(f"\n  {Colors.YELLOW}[!] Could not print summary: {exc}{Colors.RESET}")


# ---------------------------------------------------------------------------
# Interactive Menu
# ---------------------------------------------------------------------------

MENU_TEXT = f"""
{Colors.BOLD}  AI GUARDIAN - AI Security & Governance Assessment Toolkit{Colors.RESET}

  {Colors.CYAN}[1]{Colors.RESET} New Documentation Audit    {Colors.DIM}-- Assess AI governance from policies (no API needed){Colors.RESET}
  {Colors.CYAN}[2]{Colors.RESET} New Live Assessment        {Colors.DIM}-- Test an AI system via API{Colors.RESET}
  {Colors.CYAN}[3]{Colors.RESET} New Agent Assessment       {Colors.DIM}-- Test agentic AI for excessive agency{Colors.RESET}
  {Colors.CYAN}[4]{Colors.RESET} Load Saved Assessment      {Colors.DIM}-- Resume previous assessment{Colors.RESET}
  {Colors.CYAN}[5]{Colors.RESET} Generate Reports           {Colors.DIM}-- Create reports from saved assessment{Colors.RESET}
  {Colors.CYAN}[6]{Colors.RESET} Risk Classification        {Colors.DIM}-- Classify AI system under EU AI Act{Colors.RESET}
  {Colors.CYAN}[7]{Colors.RESET} Quick OWASP Scan           {Colors.DIM}-- Fast prompt injection + leakage test{Colors.RESET}
  {Colors.CYAN}[8]{Colors.RESET} View Provider Status       {Colors.DIM}-- Check available LLM provider packages{Colors.RESET}
  {Colors.CYAN}[9]{Colors.RESET} Red Team Console           {Colors.DIM}-- Interactive pentesting with advanced attacks{Colors.RESET}
  {Colors.CYAN}[0]{Colors.RESET} Exit
"""


def print_menu():
    """Print the interactive menu options."""
    print(MENU_TEXT)


def _prompt(label, default=""):
    """Prompt user for input with an optional default."""
    if default:
        raw = input(f"  {label} [{default}]: ").strip()
        return raw if raw else default
    raw = input(f"  {label}: ").strip()
    return raw


def _prompt_provider_and_connector():
    """Interactively collect provider details and build an LLM connector."""
    _check_connectors_available()
    provider = _prompt("Provider (openai/anthropic/ollama/custom)", "openai").lower().strip()
    kwargs = {}

    if provider in ("openai", "anthropic"):
        api_key = _prompt("API key")
        if api_key:
            kwargs["api_key"] = api_key
        model = _prompt("Model (press Enter for default)")
        if model:
            kwargs["model"] = model

    elif provider == "ollama":
        model = _prompt("Model", "llama3.2")
        if model:
            kwargs["model"] = model
        endpoint = _prompt("Endpoint", "http://localhost:11434")
        if endpoint:
            kwargs["endpoint"] = endpoint

    elif provider == "custom":
        endpoint = _prompt("Custom endpoint URL")
        if endpoint:
            kwargs["endpoint"] = endpoint
        api_key = _prompt("API key (optional)")
        if api_key:
            kwargs["api_key"] = api_key
        model = _prompt("Model (press Enter for default)")
        if model:
            kwargs["model"] = model

    return create_connector(provider, **kwargs)


def interactive_menu(engine, args):
    """Main interactive menu loop."""
    while True:
        print_menu()
        try:
            choice = input("  > Enter choice (1-9, 0=Exit): ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Colors.DIM}  Goodbye.{Colors.RESET}\n")
            break

        # -- [1] Documentation Audit -----------------------------------------
        if choice == "1":
            try:
                system_name = _prompt("System name", "AI System")
                org = _prompt("Organization", "Unknown")
                assessment = engine.create_assessment(
                    organization=org,
                    system_name=system_name,
                    assessor=args.assessor,
                    mode="docs",
                )
                assessment = engine.run_documentation_audit(assessment)
                _post_assessment(engine, assessment, args.output_dir)
            except Exception as exc:
                print(f"\n  {Colors.RED}[!] Documentation audit failed: {exc}{Colors.RESET}")
                traceback.print_exc()

        # -- [2] Live Assessment ---------------------------------------------
        elif choice == "2":
            try:
                system_name = _prompt("System name", "AI System")
                org = _prompt("Organization", "Unknown")
                connector = _prompt_provider_and_connector()
                sys_prompt = _prompt("System prompt to test for leakage (optional)")
                assessment = engine.create_assessment(
                    organization=org,
                    system_name=system_name,
                    assessor=args.assessor,
                    mode="live",
                )
                assessment = engine.run_live_assessment(
                    assessment, connector, system_prompt=sys_prompt
                )
                _post_assessment(engine, assessment, args.output_dir)
            except Exception as exc:
                print(f"\n  {Colors.RED}[!] Live assessment failed: {exc}{Colors.RESET}")
                traceback.print_exc()

        # -- [3] Agent Assessment --------------------------------------------
        elif choice == "3":
            try:
                system_name = _prompt("System name", "AI System")
                org = _prompt("Organization", "Unknown")
                connector = _prompt_provider_and_connector()
                sys_prompt = _prompt("System prompt to test (optional)")
                assessment = engine.create_assessment(
                    organization=org,
                    system_name=system_name,
                    assessor=args.assessor,
                    mode="agent",
                )
                assessment = engine.run_agent_assessment(
                    assessment, connector, system_prompt=sys_prompt
                )
                _post_assessment(engine, assessment, args.output_dir)
            except Exception as exc:
                print(f"\n  {Colors.RED}[!] Agent assessment failed: {exc}{Colors.RESET}")
                traceback.print_exc()

        # -- [4] Load Saved Assessment ---------------------------------------
        elif choice == "4":
            try:
                path = _prompt("JSON file path")
                if not path:
                    print(f"  {Colors.YELLOW}[!] No file path provided.{Colors.RESET}")
                    continue
                assessment = engine.import_assessment(path)
                print_summary(engine, assessment)
            except FileNotFoundError:
                print(f"  {Colors.RED}[!] File not found: {path}{Colors.RESET}")
            except Exception as exc:
                print(f"  {Colors.RED}[!] Failed to load assessment: {exc}{Colors.RESET}")

        # -- [5] Generate Reports --------------------------------------------
        elif choice == "5":
            try:
                _check_reports_available()
                path = _prompt("JSON file path")
                if not path:
                    print(f"  {Colors.YELLOW}[!] No file path provided.{Colors.RESET}")
                    continue
                assessment = engine.import_assessment(path)
                data = assessment.to_dict()
                paths = generate_all_reports(data, args.output_dir)
                print_report_paths(paths)
            except FileNotFoundError:
                print(f"  {Colors.RED}[!] File not found: {path}{Colors.RESET}")
            except Exception as exc:
                print(f"  {Colors.RED}[!] Report generation failed: {exc}{Colors.RESET}")

        # -- [6] Risk Classification -----------------------------------------
        elif choice == "6":
            try:
                _check_classifier_available()
                classifier = RiskClassifier()
                classifier.classify_interactive()
            except Exception as exc:
                print(f"  {Colors.RED}[!] Risk classification failed: {exc}{Colors.RESET}")

        # -- [7] Quick OWASP Scan --------------------------------------------
        elif choice == "7":
            try:
                _check_connectors_available()
                print(
                    f"\n  {Colors.BOLD}Quick OWASP Scan{Colors.RESET}"
                    f" {Colors.DIM}(LLM01 Prompt Injection + LLM07 System Prompt Leakage){Colors.RESET}\n"
                )
                system_name = _prompt("System name", "AI System")
                org = _prompt("Organization", "Unknown")
                connector = _prompt_provider_and_connector()
                sys_prompt = _prompt("System prompt to test for leakage (optional)")

                assessment = engine.create_assessment(
                    organization=org,
                    system_name=system_name,
                    assessor=args.assessor,
                    mode="live",
                )
                assessment = engine.run_live_assessment(
                    assessment,
                    connector,
                    categories=["LLM01", "LLM07"],
                    system_prompt=sys_prompt,
                )
                _post_assessment(engine, assessment, args.output_dir)
            except Exception as exc:
                print(f"\n  {Colors.RED}[!] Quick scan failed: {exc}{Colors.RESET}")
                traceback.print_exc()

        # -- [8] View Provider Status ----------------------------------------
        elif choice == "8":
            try:
                if check_available_providers is None:
                    print(f"  {Colors.RED}[!] llm_connectors module not available.{Colors.RESET}")
                    continue
                providers = check_available_providers()
                print(f"\n  {Colors.BOLD}LLM Provider Status:{Colors.RESET}")
                for name, available in providers.items():
                    if available:
                        status = f"{Colors.GREEN}INSTALLED{Colors.RESET}"
                    else:
                        status = f"{Colors.RED}NOT INSTALLED{Colors.RESET}"
                    print(f"    {name}: {status}")
                print()
            except Exception as exc:
                print(f"  {Colors.RED}[!] Failed to check providers: {exc}{Colors.RESET}")

        # -- [9] Red Team Console --------------------------------------------
        elif choice == "9":
            try:
                _check_connectors_available()
                print(
                    f"\n  {Colors.BOLD}Interactive Red Team Console{Colors.RESET}"
                    f" {Colors.DIM}(advanced attacks, multi-turn, encoding toolkit){Colors.RESET}\n"
                )
                connector = _prompt_provider_and_connector()
                sys_prompt = _prompt("System prompt to test against (optional)")
                try:
                    from red_team_console import launch_console
                    launch_console(connector, system_prompt=sys_prompt)
                except ImportError:
                    print(f"  {Colors.RED}[!] red_team_console module not found.{Colors.RESET}")
            except Exception as exc:
                print(f"\n  {Colors.RED}[!] Red team console failed: {exc}{Colors.RESET}")
                traceback.print_exc()

        # -- [0] Exit --------------------------------------------------------
        elif choice == "0":
            print(f"\n{Colors.DIM}  Goodbye.{Colors.RESET}\n")
            break

        else:
            print(f"  {Colors.YELLOW}[!] Invalid choice. Please enter 1-9 or 0.{Colors.RESET}")


def interactive_menu_with_assessment(engine, assessment):
    """Sub-menu when an assessment is already loaded (via --load)."""
    while True:
        print(
            f"\n  {Colors.BOLD}Loaded Assessment:{Colors.RESET} "
            f"{Colors.CYAN}{assessment.assessment_id}{Colors.RESET} "
            f"({assessment.system_name} / {assessment.organization})"
        )
        print(
            f"\n  {Colors.CYAN}[1]{Colors.RESET} View Summary"
            f"\n  {Colors.CYAN}[2]{Colors.RESET} Generate Reports"
            f"\n  {Colors.CYAN}[3]{Colors.RESET} Return to Main Menu"
            f"\n  {Colors.CYAN}[4]{Colors.RESET} Exit\n"
        )

        try:
            choice = input("  > Enter choice (1-4): ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Colors.DIM}  Goodbye.{Colors.RESET}\n")
            break

        if choice == "1":
            print_summary(engine, assessment)

        elif choice == "2":
            try:
                _check_reports_available()
                output_dir = _prompt("Output directory", "./guardian_reports")
                data = assessment.to_dict()
                paths = generate_all_reports(data, output_dir)
                print_report_paths(paths)
            except Exception as exc:
                print(f"  {Colors.RED}[!] Report generation failed: {exc}{Colors.RESET}")

        elif choice == "3":
            return "main_menu"

        elif choice == "4":
            print(f"\n{Colors.DIM}  Goodbye.{Colors.RESET}\n")
            sys.exit(0)

        else:
            print(f"  {Colors.YELLOW}[!] Invalid choice.{Colors.RESET}")

    return None


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def main():
    """Main entry point for the AI Guardian CLI."""
    print_banner()
    args = parser.parse_args()

    # --- CLI: Generate reports from a saved file ---------------------------
    if args.report:
        _check_engine_available()
        _check_reports_available()
        try:
            assessment = AssessmentEngine.import_assessment(args.report)
            data = assessment.to_dict()
            paths = generate_all_reports(data, args.output_dir)
            print_report_paths(paths)
        except FileNotFoundError:
            print(f"  {Colors.RED}[!] File not found: {args.report}{Colors.RESET}")
            sys.exit(1)
        except Exception as exc:
            print(f"  {Colors.RED}[!] Report generation failed: {exc}{Colors.RESET}")
            traceback.print_exc()
            sys.exit(1)
        return

    # --- CLI: Load a saved assessment --------------------------------------
    if args.load:
        _check_engine_available()
        engine = AssessmentEngine()
        try:
            assessment = engine.import_assessment(args.load)
        except FileNotFoundError:
            print(f"  {Colors.RED}[!] File not found: {args.load}{Colors.RESET}")
            sys.exit(1)
        except Exception as exc:
            print(f"  {Colors.RED}[!] Failed to load assessment: {exc}{Colors.RESET}")
            traceback.print_exc()
            sys.exit(1)

        if args.summary:
            print_summary(engine, assessment)
        else:
            result = interactive_menu_with_assessment(engine, assessment)
            if result == "main_menu":
                interactive_menu(engine, args)
        return

    # --- CLI: Start a new assessment (--new) --------------------------------
    if args.new:
        _check_engine_available()
        engine = AssessmentEngine()

        # Determine assessment mode
        if args.live:
            mode = "live"
        elif args.agent:
            mode = "agent"
        else:
            mode = "docs"

        try:
            assessment = engine.create_assessment(
                organization=args.org or "Unknown",
                system_name=args.new,
                assessor=args.assessor,
                mode=mode,
            )

            if mode == "docs":
                assessment = engine.run_documentation_audit(assessment)

            elif mode in ("live", "agent"):
                connector = _build_connector(args)
                if mode == "live":
                    categories = _parse_attack_categories(args.attacks)
                    assessment = engine.run_live_assessment(
                        assessment,
                        connector,
                        categories=categories,
                        system_prompt=args.system_prompt or "",
                    )
                else:
                    assessment = engine.run_agent_assessment(
                        assessment,
                        connector,
                        system_prompt=args.system_prompt or "",
                    )

            # Save and generate reports
            _check_reports_available()
            save_path = _save_assessment(engine, assessment, args.output_dir)
            data = assessment.to_dict()
            paths = generate_all_reports(data, args.output_dir)
            print_report_paths(paths)

        except KeyboardInterrupt:
            print(f"\n\n  {Colors.YELLOW}[!] Assessment interrupted by user.{Colors.RESET}")
            sys.exit(130)
        except Exception as exc:
            print(f"\n  {Colors.RED}[!] Assessment failed: {exc}{Colors.RESET}")
            traceback.print_exc()
            sys.exit(1)
        return

    # --- No CLI args: Interactive menu -------------------------------------
    _check_engine_available()
    engine = AssessmentEngine()
    try:
        interactive_menu(engine, args)
    except KeyboardInterrupt:
        print(f"\n\n{Colors.DIM}  Goodbye.{Colors.RESET}\n")


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
