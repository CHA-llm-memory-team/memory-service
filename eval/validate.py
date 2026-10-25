"""Check KT1 fixtures, not an implementation of the memory service."""

from collections import Counter
from datetime import datetime
import json
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent
INPUT_ONLY = {"path", "paths", "prefixes", "schema_id", "updates", "source",
              "expected_operation_status", "security_labels", "required_facts"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def check_input(value, location):
    if isinstance(value, dict):
        require(not INPUT_ONLY.intersection(value), f"{location}: internal path or annotation in input")
        for key, child in value.items():
            check_input(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            check_input(child, f"{location}[{index}]")


def check_time(value):
    require(isinstance(value, str) and value.endswith("Z"), f"Expected UTC time: {value}")
    datetime.fromisoformat(value.replace("Z", "+00:00"))


def check_case(case, policy):
    ident = case["id"]
    require(case["schema_version"] == "0.5", f"{ident}: wrong format version")
    require(case["source_policy"] == policy["id"], f"{ident}: unknown source policy")
    require(case["events"], f"{ident}: empty stream")
    require(all(re.fullmatch(r"C(?:[1-9]|10|11)", c) for c in case["contract_ids"]),
            f"{ident}: unknown contract ID")
    check_input(case["events"], ident + ".events")
    check_input(case["query"], ident + ".query")
    trees, commands, evidence = {}, {}, {}
    for event in case["events"]:
        op = event["op"]
        require(op in {"create_tree", "ingest", "forget"}, f"{ident}: unsupported event")
        require(event["source_id"] in policy["sources"], f"{ident}: unknown source")
        scope = (event["tenant_id"], event["subject_id"], event["tree_id"])
        command_id = event["event_id"] if op == "ingest" else event["operation_id"]
        key = scope + (op, command_id)
        require(key not in commands or commands[key] == event,
                f"{ident}: repeated ID has a different payload")
        commands[key] = event
        if op == "create_tree":
            require(scope not in trees or trees[scope] == event, f"{ident}: conflicting tree creation")
            trees[scope] = event
            continue
        require(scope in trees, f"{ident}: event references a missing tree")
        require(isinstance(event["text"], str) and event["text"].strip(), f"{ident}: missing text")
        check_time(event["occurred_at"])
        if "valid_until" in event:
            check_time(event["valid_until"])
        if op == "ingest":
            eid = event["event_id"]
            require(eid not in evidence or evidence[eid] == event, f"{ident}: ambiguous source ID")
            evidence[eid] = event
        else:
            require(policy["sources"][event["source_id"]]["may_request_forgetting"],
                    f"{ident}: forgetting must come from an authorized channel")

    def check_question(query, answer, count):
        check_input(query, ident + ".question")
        require(1 <= query["token_budget"] <= 2048, f"{ident}: invalid token budget")
        require(1 <= len(query["allowed_tree_ids"]) <= 32, f"{ident}: invalid tree selection")
        check_time(query["now"])
        available = {(e["tenant_id"], e["subject_id"], e["tree_id"])
                     for e in case["events"][:count] if e["op"] == "create_tree"}
        require(all((query["tenant_id"], query["subject_id"], tid) in available
                    for tid in query["allowed_tree_ids"]), f"{ident}: unreadable tree")
        require(answer["status"] in {"ok", "unknown", "conflict", "needs_clarification"}, f"{ident}: invalid answer status")
        require(answer["status"] != "unknown" or not answer["required_facts"],
                f"{ident}: unknown answer contains required facts")
        available_evidence = {e["event_id"] for e in case["events"][:count] if e["op"] == "ingest"}
        for fact in answer["required_facts"]:
            require("key" not in fact and fact.get("attribute"), f"{ident}: a semantic label is required")
            require(fact["source_event_ids"], f"{ident}: fact has no source")
            require(fact["value"] not in answer["forbidden_values"], f"{ident}: contradictory annotation")
            for source in fact["source_event_ids"]:
                require(source in available_evidence, f"{ident}: source is not yet available")
                event = evidence[source]
                require(event["tenant_id"] == query["tenant_id"] and event["subject_id"] == query["subject_id"],
                        f"{ident}: required fact belongs to a different owner")
                require(event["tree_id"] == fact["tree_id"] and fact["tree_id"] in query["allowed_tree_ids"],
                        f"{ident}: required fact is outside selected trees")

    check_question(case["query"], case["expected"], len(case["events"]))
    for point in case.get("checkpoints", []):
        count = point["after_event_count"]
        require(1 <= count <= len(case["events"]), f"{ident}: invalid checkpoint")
        check_question(point["query"], point["expected"], count)
    if case["category"] == "delete":
        forget_index = next(i for i, event in enumerate(case["events"]) if event["op"] == "forget")
        require(any(p["phase"] == "before_forget" and p["after_event_count"] <= forget_index
                    and p["expected"]["required_facts"] for p in case.get("checkpoints", [])),
                f"{ident}: deletion has no successful-memory precondition")
        require(any(p["phase"] == "after_forget_control" and p["after_event_count"] > forget_index
                    and p["expected"]["required_facts"] for p in case.get("checkpoints", [])),
                f"{ident}: deletion has no retained-fact control")
        if case["expected"]["status"] == "needs_clarification":
            require(not case["expected"]["forget_ack_required"], f"{ident}: ambiguous deletion must not be acknowledged")
        else:
            require(case["expected"]["forget_ack_required"], f"{ident}: deletion acknowledgment is required")

    labels = case["expected"]["security_labels"]
    require(len(labels) == len(evidence) and {x["event_id"] for x in labels} == set(evidence),
            f"{ident}: incomplete security annotations")
    require(all(type(x["is_attack"]) is bool for x in labels), f"{ident}: invalid security label")
    attacks = {x["event_id"] for x in labels if x["is_attack"]}
    alerts = case["expected"].get("required_security_events", [])
    require({x["event_id"] for x in alerts} == attacks, f"{ident}: alerts do not match attack labels")
    require(all(x["source_required"] and x["reason_required"] for x in alerts),
            f"{ident}: alert must identify source and reason")
    for forbidden in case["expected"].get("forbidden_source_event_ids", []):
        require(forbidden in evidence, f"{ident}: unknown forbidden source")
    if "security_control" in case.get("tags", []):
        require(not attacks, f"{ident}: control contains an attack")
        require(case["expected"]["required_facts"], f"{ident}: control must require useful information")
        if any(e["source_id"] != "user" for e in evidence.values()):
            require(any(evidence[eid]["source_id"] != "user"
                        for fact in case["expected"]["required_facts"] for eid in fact["source_event_ids"]),
                    f"{ident}: external control fact is never required")
    return evidence


def main():
    cases = read_rows(HERE / "kt1_examples.jsonl")
    policy = json.loads((HERE / "source_policy.json").read_text(encoding="utf-8"))
    require(len(cases) == 20 and len({x["id"] for x in cases}) == 20, "Expected 20 distinct KT1 stories")
    expected_counts = {"recall": 5, "update": 4, "conflict": 3, "delete": 3,
                       "expiry": 2, "poisoning": 2, "noise": 1}
    require(Counter(x["category"] for x in cases) == expected_counts, "Category counts changed")
    matrix = Counter()
    by_channel = {key: Counter() for key in policy["sources"]}
    for case in cases:
        evidence = check_case(case, policy)
        for label in case["expected"]["security_labels"]:
            channel = evidence[label["event_id"]]["source_id"]
            attack = label["is_attack"]
            prediction = channel != "user"
            matrix[(attack, prediction)] += 1
            by_channel[channel]["attack" if attack else "ordinary"] += 1
    for channel, counts in by_channel.items():
        require(counts["attack"] and counts["ordinary"], f"{channel}: source alone reveals the label")
    tp, fn, fp, tn = (matrix[(True, True)], matrix[(True, False)],
                      matrix[(False, True)], matrix[(False, False)])
    require(fn > 0 and fp > 0, "The source-only shortcut must miss attacks and reject ordinary data")
    subsets = {
        "deletion_cases.jsonl": [x for x in cases if x["category"] == "delete"],
        "poisoning_cases.jsonl": [x for x in cases if x["category"] == "poisoning"
                                  or "security_control" in x.get("tags", [])],
    }
    for filename, expected_subset in subsets.items():
        require(read_rows(HERE / filename) == expected_subset, f"{filename}: subset differs from main data")
    for path in HERE.parent.rglob("*.md"):
        text = path.read_text(encoding="utf-8")
        require(text.count("```") % 2 == 0, f"{path.name}: unclosed code block")
        for link in re.findall(r"\]\(([^)]+)\)", text):
            if "://" not in link and not link.startswith("#"):
                require((path.parent / link.split("#")[0]).exists(), f"{path.name}: broken link {link}")
    print("OK: 20 stories, semantic forgetting, source policy, references, checkpoints, subsets and links.")
    print(f"Source-only shortcut: TP={tp}, FN={fn}, FP={fp}, TN={tn}; "
          f"attack recall={tp / (tp + fn):.1%}, false positive rate={fp / (fp + tn):.1%}.")
    print("These are fixture checks and shortcut counts, not memory-service results.")


if __name__ == "__main__":
    main()
