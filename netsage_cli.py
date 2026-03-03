"""NetSage CLI: recursive backward-chaining LAN diagnosis with certainty factors."""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


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
        self.gateway_ip = gateway_ip
        self.dns_ip = dns_ip
        self.allow_questions = True

    def set_fact(self, fact: str, value: Any, cf: float = 1.0) -> None:
        self.facts[fact] = {"value": value, "cf": max(0.0, min(1.0, float(cf)))}

    @staticmethod
    def combine_cf(cf_old: float, cf_new: float) -> float:
        """Shortliffe/MYCIN combination formula for positive evidence."""
        return cf_old + cf_new * (1.0 - cf_old)

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
            self.ask_user(fact, goal, rule)
            return self.facts[fact]
        self.facts[fact] = {"value": None, "cf": 0.0}
        return self.facts[fact]

    def _probe_ping(self, ip: str) -> bool | None:
        try:
            proc = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
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
        asked_probe, probed_value = self.auto_probe(fact)
        if asked_probe:
            cf = 1.0 if isinstance(probed_value, (bool, str)) else max(0.0, min(1.0, float(probed_value)))
            self.set_fact(fact, probed_value, cf)
            if fact == "no_gateway_ping" and isinstance(probed_value, bool):
                self.set_fact("no_gateway_ping", not probed_value, 1.0)
            return

        node = self.questions.get(fact)
        if not node:
            value = input(f"Provide confidence for '{fact}' (0.0-1.0): ").strip()
            cf = float(value)
            self.set_fact(fact, cf, cf)
            return

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
                if fact == "no_gateway_ping" and isinstance(value, bool):
                    self.set_fact("no_gateway_ping", not value, 1.0)
                break
            except ValueError as exc:
                print(exc)

    def evaluate(self, goal: str) -> float:
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
            applied_cf = self.combine_cf(applied_cf, contribution)
            self.trace.append(
                RuleResult(
                    goal=goal,
                    rule_id=rule["id"],
                    contribution_cf=contribution,
                    explanation=rule["explanation"],
                )
            )
        return applied_cf

    def infer_all(self) -> dict[str, float]:
        self.trace.clear()
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
        if low in {"y", "yes", "true", "1"}:
            return True
        if low in {"n", "no", "false", "0"}:
            return False
        raise ValueError("Please enter yes/no")
    if ntype == "numeric":
        return float(answer)
    if ntype == "choice":
        choices = node.get("choices", [])
        if answer not in choices:
            raise ValueError(f"Choose one of: {', '.join(choices)}")
        return answer
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


def main() -> None:
    parser = argparse.ArgumentParser(description="NetSage LAN diagnostic expert system")
    parser.add_argument("--rules", default="knowledge/lan_rules.json")
    parser.add_argument("--questions", default="knowledge/question_graph.json")
    parser.add_argument("--gateway-ip", default="192.168.1.1")
    parser.add_argument("--dns-ip", default="8.8.8.8")
    parser.add_argument("--goal", default="no_internet", help="Primary diagnosis goal for --demo mode")
    parser.add_argument("--facts", help="JSON object of known facts")
    parser.add_argument("--demo", action="store_true", help="Run deterministic demo scenario")
    args = parser.parse_args()

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

    if args.facts:
        system.allow_questions = False
        for name, value in json.loads(args.facts).items():
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
