"""NetSage CLI: recursive backward-chaining LAN diagnosis with certainty factors."""

from __future__ import annotations

import argparse
import json
import math
import platform
import subprocess
from dataclasses import dataclass
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs


@dataclass
class RuleResult:
    goal: str
    rule_id: str
    contribution_cf: float
    explanation: str


class ExpertSystem:
    def __init__(self, rules_path: Path, questions_path: Path, gateway_ip: str, dns_ip: str) -> None:
        with rules_path.open("r", encoding="utf-8") as fh:
            self.kb = json.load(fh)
        with questions_path.open("r", encoding="utf-8") as fh:
            q = json.load(fh)

        self.questions = {item["fact"]: item for item in q["facts"]}
        self.rules_by_goal: dict[str, list[dict[str, Any]]] = {}
        for rule in self.kb["rules"]:
            self.rules_by_goal.setdefault(rule["then"], []).append(rule)

        self.facts: dict[str, dict[str, Any]] = {}
        self.trace: list[RuleResult] = []
        self._eval_cache: dict[str, float] = {}
        self.gateway_ip = gateway_ip
        self.dns_ip = dns_ip
        self.allow_questions = True
        self._explained_facts: set[str] = set()
        self.fact_frequency = self._build_fact_frequency()

    def _build_fact_frequency(self) -> dict[str, int]:
        frequency: dict[str, int] = {}
        for rule in self.kb["rules"]:
            for cond in rule["if"]:
                fact = cond["fact"]
                frequency[fact] = frequency.get(fact, 0) + 1
        return frequency

    def set_fact(self, fact: str, value: Any, cf: float = 1.0) -> None:
        self.facts[fact] = {"value": value, "cf": max(0.0, min(1.0, float(cf)))}

    @staticmethod
    def combine_cf(cf_old: float, cf_new: float) -> float:
        """Shortliffe/MYCIN combination formula for positive evidence."""
        return cf_old + cf_new * (1.0 - cf_old)

    def combine_weighted_cf(self, cf_old: float, cf_new: float, weight: float = 1.0) -> float:
        safe_weight = max(0.0, min(1.0, float(weight)))
        return self.combine_cf(cf_old, cf_new * safe_weight)

    @staticmethod
    def _condition_match(actual: Any, op: str, expected: Any) -> bool:
        if op == "==":
            return actual == expected
        if op == "!=":
            return actual != expected
        if op == ">=":
            return actual >= expected
        if op == "<=":
            return actual <= expected
        if op == ">":
            return actual > expected
        if op == "<":
            return actual < expected
        raise ValueError(f"Unsupported operator: {op}")

    def _ensure_fact(self, fact: str, goal: str, rule: dict[str, Any]) -> dict[str, Any]:
        if fact in self.facts:
            return self.facts[fact]

        if fact in self.rules_by_goal:
            inferred = self.evaluate(fact)
            self.set_fact(fact, inferred, inferred)
            return self.facts[fact]

        if self.allow_questions:
            selected_fact = self.select_next_fact(goal, fallback_fact=fact)
            self.ask_user(selected_fact, goal, rule)
            if fact not in self.facts:
                self.ask_user(fact, goal, rule)
            return self.facts[fact]
        self.facts[fact] = {"value": None, "cf": 0.0}
        return self.facts[fact]

    def _collect_candidate_facts(self, goal: str, depth: int = 0, max_depth: int = 2) -> set[str]:
        if depth > max_depth:
            return set()

        candidates: set[str] = set()
        for rule in self.rules_by_goal.get(goal, []):
            for cond in rule["if"]:
                fact = cond["fact"]
                if fact in self.facts:
                    continue
                if fact in self.rules_by_goal:
                    candidates.update(self._collect_candidate_facts(fact, depth + 1, max_depth))
                else:
                    candidates.add(fact)
        return candidates

    def _fact_info_gain_score(self, fact: str) -> float:
        node = self.questions.get(fact, {})
        importance = float(node.get("importance", 0.5))
        related_rules = len(node.get("related_rules", []))
        reuse_count = self.fact_frequency.get(fact, 0)
        auto_probe_bonus = 0.15 if node.get("auto_probe") else 0.0

        normalized_related = min(related_rules, 6) / 6.0
        normalized_reuse = min(reuse_count, 6) / 6.0

        entropy_proxy = 1.0
        if node.get("type") == "choice":
            options = max(1, len(node.get("choices", [])))
            entropy_proxy = min(1.0, math.log2(options + 1) / 2.0)

        return (importance * 0.45) + (normalized_related * 0.2) + (normalized_reuse * 0.2) + (entropy_proxy * 0.15) + auto_probe_bonus

    def select_next_fact(self, goal: str, fallback_fact: str) -> str:
        if fallback_fact in self.facts:
            return fallback_fact

        candidates = self._collect_candidate_facts(goal)
        if not candidates:
            return fallback_fact
        return max(candidates, key=self._fact_info_gain_score)

    def _probe_ping(self, ip: str) -> bool | None:
        try:
            if platform.system().lower().startswith("win"):
                cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
            return proc.returncode == 0
        except FileNotFoundError:
            return None

    def _probe_interface_status(self) -> str | None:
        try:
            proc = subprocess.run(
                ["sh", "-c", "ip route show default | awk '{print $5}' | head -n1"],
                capture_output=True,
                text=True,
                check=False,
            )
            iface = proc.stdout.strip()
            if not iface:
                return None
            link = subprocess.run(
                ["cat", f"/sys/class/net/{iface}/operstate"],
                capture_output=True,
                text=True,
                check=False,
            )
            state = link.stdout.strip().lower()
            if state in {"up", "down"}:
                return state
            return None
        except FileNotFoundError:
            return None

    def auto_probe(self, fact: str) -> tuple[bool, Any]:
        node = self.questions.get(fact, {})
        probe = node.get("auto_probe")
        if probe == "gateway_ping":
            val = self._probe_ping(self.gateway_ip)
            if val is not None:
                return True, val
        if probe == "dns_reachable":
            val = self._probe_ping(self.dns_ip)
            if val is not None:
                return True, val
        if probe == "interface_status":
            val = self._probe_interface_status()
            if val is not None:
                return True, val
        return False, None

    @staticmethod
    def _fuzzy_membership(value: float, points: list[dict[str, float]]) -> float:
        for p in points:
            if "lte" in p and value <= p["lte"]:
                return float(p["cf"])
            if "gt" in p and value > p["gt"]:
                return float(p["cf"])
        return 0.0

    def _apply_fuzzy_derivations(self, fact: str, raw_value: float) -> None:
        node = self.questions.get(fact, {})
        fuzzy = node.get("fuzzy", {})
        derive = fuzzy.get("derive", {})
        for derived_fact, points in derive.items():
            cf = self._fuzzy_membership(raw_value, points)
            self.set_fact(derived_fact, cf, cf)

    def ask_user(self, fact: str, goal: str, rule: dict[str, Any]) -> None:
        if fact in self.facts:
            return

        asked_probe, probed_value = self.auto_probe(fact)
        if asked_probe:
            cf = 1.0 if isinstance(probed_value, (bool, str)) else max(0.0, min(1.0, float(probed_value)))
            if fact == "no_gateway_ping" and isinstance(probed_value, bool):
                self.set_fact("no_gateway_ping", not probed_value, 1.0)
            else:
                self.set_fact(fact, probed_value, cf)
            return

        node = self.questions.get(fact)
        if not node:
            value = input(f"Provide confidence for '{fact}' (0.0-1.0): ").strip()
            cf = float(value)
            self.set_fact(fact, cf, cf)
            return

        if fact not in self._explained_facts:
            explanation = node.get("user_explanation")
            if explanation:
                print(f"Why this question: {explanation}")
            self._explained_facts.add(fact)

        while True:
            raw = input(f"{node['question']} (or type 'why'): ").strip()
            if raw.lower() == "why":
                print(
                    f"WHY: trying to prove '{goal}'. Rule {rule['id']} says {rule['then']} when "
                    f"its conditions hold (rule CF={rule['cf']}). Need fact '{fact}'."
                )
                continue
            try:
                value = parse_answer(node, raw)
                self.set_fact(fact, value, 1.0)
                if node["type"] == "numeric":
                    self._apply_fuzzy_derivations(fact, float(value))
                break
            except ValueError as exc:
                print(exc)

    def evaluate(self, goal: str) -> float:
        if goal in self._eval_cache:
            return self._eval_cache[goal]

        applied_cf = 0.0
        for rule in self.rules_by_goal.get(goal, []):
            condition_cfs: list[float] = []
            rule_valid = True
            for cond in rule["if"]:
                entry = self._ensure_fact(cond["fact"], goal, rule)
                actual = entry["value"]
                if actual is None or not self._condition_match(actual, cond["op"], cond["value"]):
                    rule_valid = False
                    break
                condition_cfs.append(entry["cf"])

            if not rule_valid or not condition_cfs:
                continue

            strength = min(condition_cfs)
            contribution = strength * float(rule["cf"])
            applied_cf = self.combine_weighted_cf(applied_cf, contribution, float(rule.get("weight", 1.0)))
            self.trace.append(
                RuleResult(
                    goal=goal,
                    rule_id=rule["id"],
                    contribution_cf=contribution,
                    explanation=rule["explanation"],
                )
            )
        self._eval_cache[goal] = applied_cf
        return applied_cf

    def infer_all(self) -> dict[str, float]:
        self.trace.clear()
        self._eval_cache.clear()
        scores: dict[str, float] = {}
        for goal in self.kb["goals"]:
            score = self.evaluate(goal)
            self.set_fact(goal, score, score)
            scores[goal] = score
        return scores


def parse_answer(node: dict[str, Any], answer: str) -> Any:
    ntype = node["type"]
    if ntype in {"boolean", "boolean_inverted"}:
        low = answer.lower()
        parsed: bool
        if low in {"y", "yes", "true", "1"}:
            parsed = True
        elif low in {"n", "no", "false", "0"}:
            parsed = False
        else:
            raise ValueError("Please enter yes/no")
        if ntype == "boolean_inverted":
            return not parsed
        return parsed
    if ntype == "numeric":
        return float(answer)
    if ntype == "choice":
        choices = [str(choice) for choice in node.get("choices", [])]
        normalized = {choice.lower(): choice for choice in choices}
        low = answer.strip().lower()
        if low not in normalized:
            raise ValueError(f"Choose one of: {', '.join(choices)}")
        return normalized[low]
    raise ValueError(f"Unsupported question type: {ntype}")


def print_report(scores: dict[str, float], trace: list[RuleResult]) -> None:
    print("\nDiagnosis ranking:")
    for goal, cf in sorted(scores.items(), key=lambda x: x[1], reverse=True):
        print(f"- {goal}: CF={cf:.2f}")

    print("\nFired rules:")
    if not trace:
        print("- (none)")
        return
    for step in trace:
        print(f"- {step.rule_id} -> {step.goal} (+{step.contribution_cf:.2f}): {step.explanation}")


def _render_web_form(
    system: ExpertSystem,
    goal: str = "no_internet",
    result_html: str = "",
    current_values: dict[str, str] | None = None,
) -> str:
    values = current_values or {}
    fields: list[str] = []
    hidden_facts = {"no_gateway_ping"}
    for node in system.questions.values():
        fact_name = node["fact"]
        if fact_name in hidden_facts:
            continue
        question = escape(node["question"])
        explainer = escape(node.get("user_explanation", ""))
        ntype = node["type"]
        current = values.get(fact_name, "")

        if ntype in {"boolean", "boolean_inverted"}:
            yes_selected = " selected" if current.lower() in {"yes", "true", "1", "y"} else ""
            no_selected = " selected" if current.lower() in {"no", "false", "0", "n"} else ""
            control = (
                f"<select name='{escape(fact_name)}' class='control'>"
                "<option value=''>Unknown</option>"
                f"<option value='yes'{yes_selected}>Yes</option>"
                f"<option value='no'{no_selected}>No</option>"
                "</select>"
            )
        elif ntype == "choice":
            options: list[str] = ["<option value=''>Unknown</option>"]
            for choice in node.get("choices", []):
                choice_str = str(choice)
                selected = " selected" if current.lower() == choice_str.lower() else ""
                options.append(f"<option value='{escape(choice_str)}'{selected}>{escape(choice_str)}</option>")
            control = f"<select name='{escape(fact_name)}' class='control'>{''.join(options)}</select>"
        elif ntype == "numeric":
            control = (
                f"<input type='number' step='any' name='{escape(fact_name)}' class='control' "
                f"placeholder='Numeric value' value='{escape(current)}' />"
            )
        else:
            control = f"<input type='text' name='{escape(fact_name)}' class='control' value='{escape(current)}' />"

        fields.append(
            "<article class='fact-card'>"
            f"<label class='fact-label'>{question}</label>"
            f"{control}"
            f"<p class='fact-help'>{explainer}</p>"
            "</article>"
        )

    return (
        "<html><head><title>NetSage Web</title>"
        "<style>"
        "*{box-sizing:border-box;}"
        "body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:linear-gradient(145deg,#0f172a,#111827);color:#e5e7eb;}"
        ".container{max-width:1100px;margin:28px auto;padding:0 18px;}"
        ".panel{background:#111827;border:1px solid #1f2937;border-radius:16px;box-shadow:0 16px 30px rgba(0,0,0,.25);padding:22px;}"
        ".header{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;margin-bottom:18px;}"
        ".title{margin:0;font-size:1.8rem;color:#f9fafb;}"
        ".subtitle{margin:6px 0 0;color:#9ca3af;}"
        ".pill{background:#1d4ed8;color:#dbeafe;border-radius:999px;padding:8px 12px;font-size:.85rem;white-space:nowrap;}"
        ".goal-wrap{margin:14px 0 18px;}"
        ".goal-label{display:block;font-weight:600;margin-bottom:8px;color:#cbd5e1;}"
        ".control{width:100%;padding:11px 12px;border-radius:10px;border:1px solid #374151;background:#0b1220;color:#f3f4f6;outline:none;}"
        ".control:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.2);}"
        ".facts-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;}"
        ".fact-card{background:#0b1220;border:1px solid #1f2937;border-radius:12px;padding:12px;}"
        ".fact-label{display:block;font-weight:600;font-size:.95rem;margin-bottom:8px;color:#e2e8f0;}"
        ".fact-help{margin:8px 0 0;font-size:.82rem;color:#94a3b8;line-height:1.35;}"
        ".actions{margin-top:16px;display:flex;gap:10px;align-items:center;}"
        ".btn{border:0;border-radius:10px;padding:11px 14px;font-weight:700;cursor:pointer;background:#2563eb;color:white;}"
        ".btn:hover{background:#1d4ed8;}"
        ".hint{font-size:.85rem;color:#94a3b8;}"
        ".result{margin-top:18px;padding-top:16px;border-top:1px solid #1f2937;}"
        ".result-title{margin:0 0 10px;color:#f8fafc;}"
        ".score{display:inline-block;border-radius:10px;background:#064e3b;color:#d1fae5;padding:4px 8px;margin-left:8px;font-size:.9rem;}"
        ".result-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px;}"
        ".card{background:#0b1220;border:1px solid #1f2937;border-radius:12px;padding:12px;}"
        ".card h3{margin:0 0 8px;color:#e2e8f0;font-size:1rem;}"
        ".list{margin:0;padding-left:18px;color:#cbd5e1;}"
        ".list li{margin-bottom:6px;line-height:1.35;}"
        "</style></head><body><main class='container'><section class='panel'>"
        "<header class='header'><div><h1 class='title'>NetSage Diagnosis</h1>"
        "<p class='subtitle'>Enter known values and leave unknowns blank.</p></div>"
        "<span class='pill'>LAN + WAN Expert System</span></header>"
        "<form method='POST' action='/diagnose'>"
        "<div class='goal-wrap'><label class='goal-label'>Primary Goal</label>"
        f"<input name='goal' class='control' value='{escape(goal)}' /></div>"
        f"<section class='facts-grid'>{''.join(fields)}</section>"
        "<div class='actions'><button class='btn' type='submit'>Run Diagnosis</button>"
        "<span class='hint'>Tip: Start with facts you already know.</span></div></form>"
        f"{result_html}</section></main>"
        "</body></html>"
    )


def run_web_app(args: argparse.Namespace) -> None:
    rules_path = Path(args.rules)
    questions_path = Path(args.questions)

    class NetSageHandler(BaseHTTPRequestHandler):
        def _send_html(self, html: str, status: int = 200) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))

        def do_GET(self) -> None:  # noqa: N802
            if self.path != "/":
                self._send_html("<h1>Not Found</h1>", status=404)
                return
            system = ExpertSystem(rules_path, questions_path, args.gateway_ip, args.dns_ip)
            self._send_html(_render_web_form(system))

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/diagnose":
                self._send_html("<h1>Not Found</h1>", status=404)
                return

            content_length = int(self.headers.get("Content-Length", "0"))
            payload = self.rfile.read(content_length).decode("utf-8")
            form = parse_qs(payload)
            goal = form.get("goal", ["no_internet"])[0] or "no_internet"
            current_values: dict[str, str] = {"goal": goal}

            system = ExpertSystem(rules_path, questions_path, args.gateway_ip, args.dns_ip)
            system.allow_questions = False

            for fact_name, node in system.questions.items():
                raw_value = form.get(fact_name, [""])[0].strip()
                current_values[fact_name] = raw_value
                if raw_value == "":
                    continue
                try:
                    parsed = parse_answer(node, raw_value)
                    system.set_fact(fact_name, parsed)
                    if node.get("type") == "numeric":
                        system._apply_fuzzy_derivations(fact_name, float(parsed))
                except ValueError:
                    continue

            if "gateway_ping" in system.facts and isinstance(system.facts["gateway_ping"]["value"], bool):
                gateway_ok = system.facts["gateway_ping"]["value"]
                system.set_fact("no_gateway_ping", not gateway_ok, 1.0)

            top = system.evaluate(goal)
            scores = system.infer_all()

            ranking_html = "".join(
                f"<li><strong>{escape(name)}</strong>: CF={score:.2f}</li>"
                for name, score in sorted(scores.items(), key=lambda item: item[1], reverse=True)
            )
            rules_html = (
                "".join(
                    f"<li><strong>{escape(step.rule_id)}</strong> -> {escape(step.goal)} (+{step.contribution_cf:.2f})<br/>{escape(step.explanation)}</li>"
                    for step in system.trace
                )
                if system.trace
                else "<li>(none)</li>"
            )

            result_html = (
                "<section class='result'>"
                f"<h2 class='result-title'>Goal: {escape(goal)} <span class='score'>CF {top:.2f}</span></h2>"
                "<div class='result-grid'>"
                "<article class='card'><h3>Diagnosis Ranking</h3><ol class='list'>"
                f"{ranking_html}</ol></article>"
                "<article class='card'><h3>Fired Rules</h3><ul class='list'>"
                f"{rules_html}</ul></article></div></section>"
            )

            self._send_html(_render_web_form(system, goal=goal, result_html=result_html, current_values=current_values))

    server = HTTPServer((args.host, args.port), NetSageHandler)
    print(f"NetSage web form running at http://{args.host}:{args.port}")
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="NetSage LAN diagnostic expert system")
    parser.add_argument("--rules", default="knowledge/lan_rules.json")
    parser.add_argument("--questions", default="knowledge/question_graph.json")
    parser.add_argument("--gateway-ip", default="192.168.1.1")
    parser.add_argument("--dns-ip", default="8.8.8.8")
    parser.add_argument("--goal", default="no_internet", help="Primary diagnosis goal for --demo mode")
    parser.add_argument("--web", action="store_true", help="Run a local web form for diagnosis")
    parser.add_argument("--host", default="127.0.0.1", help="Web host used with --web")
    parser.add_argument("--port", type=int, default=8000, help="Web port used with --web")
    parser.add_argument(
        "--facts",
        nargs="?",
        const="{}",
        help="Optional JSON object of known facts. Use --facts alone to run with no preset facts.",
    )
    parser.add_argument("--demo", action="store_true", help="Run deterministic demo scenario")
    args = parser.parse_args()

    if args.web:
        run_web_app(args)
        return

    system = ExpertSystem(Path(args.rules), Path(args.questions), args.gateway_ip, args.dns_ip)

    if args.demo:
        system.set_fact("gateway_ping", True)
        system.set_fact("no_gateway_ping", False)
        system.set_fact("dns_reachable", False)
        system.set_fact("latency_ms", 180, 1.0)
        system._apply_fuzzy_derivations("latency_ms", 180)
        system.set_fact("interference_dbm", -62, 1.0)
        system._apply_fuzzy_derivations("interference_dbm", -62)
        system.allow_questions = False
        top = system.evaluate(args.goal)
        print(f"Goal '{args.goal}' CF={top:.2f}")
        print_report(system.infer_all(), system.trace)
        return

    if args.facts is not None:
        system.allow_questions = False
        try:
            known_facts = json.loads(args.facts)
        except json.JSONDecodeError as exc:
            parser.error(f"--facts must be valid JSON object: {exc.msg}")
        if not isinstance(known_facts, dict):
            parser.error("--facts must be a JSON object, e.g. --facts '{\"gateway_ping\": true}'")

        for name, value in known_facts.items():
            system.set_fact(name, value)
            node = system.questions.get(name)
            if node and node.get("type") == "numeric":
                system._apply_fuzzy_derivations(name, float(value))
        print_report(system.infer_all(), system.trace)
        return

    score = system.evaluate(args.goal)
    print(f"\nPrimary goal '{args.goal}' evaluated to CF={score:.2f}")
    print_report(system.infer_all(), system.trace)


if __name__ == "__main__":
    main()
