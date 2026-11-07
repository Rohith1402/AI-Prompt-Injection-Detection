
import os
import csv
import re
from datetime import datetime


# ==========================================
# CONFIGURATION
# ==========================================

LOG_FILE = "ai_security.log"
CSV_FILE = "soc_security_report.csv"

RECENT_EVENT_LIMIT = 5

HIGH_RISK_THRESHOLD = 70
MEDIUM_RISK_THRESHOLD = 30


# ==========================================
# ATTACK BEHAVIOR MAPPING
# ==========================================

ATTACK_MAPPING = {

    "instruction_override": {
        "behavior": "Instruction Override",
        "description": (
            "Attempt to manipulate the AI's instructions"
        ),
        "framework": "MITRE ATLAS",
        "technique": "Prompt Injection"
    },

    "data_exfiltration": {
        "behavior": "Sensitive Data Disclosure",
        "description": (
            "Attempt to access or disclose protected information"
        ),
        "framework": "Security Behavior",
        "technique": "Data Disclosure"
    },

    "security_bypass": {
        "behavior": "Security Control Bypass",
        "description": (
            "Attempt to bypass security restrictions"
        ),
        "framework": "Security Behavior",
        "technique": "Security Bypass"
    }
}


# ==========================================
# READ SECURITY LOGS
# ==========================================

def read_security_logs():
    """Read security logs from the log file."""

    if not os.path.exists(LOG_FILE):

        print(f"Log file not found: {LOG_FILE}")

        return []

    with open(
        LOG_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return file.readlines()


# ==========================================
# TIMESTAMP EXTRACTION
# ==========================================

def extract_timestamp(log):
    """Extract timestamp from security log."""

    match = re.search(
        r"^(\d{4}-\d{2}-\d{2} "
        r"\d{2}:\d{2}:\d{2})",
        log
    )

    if match:

        return match.group(1)

    return "UNKNOWN"


# ==========================================
# SUSPICIOUS LOG DETECTION
# ==========================================

def is_suspicious_log(log):
    """Recognize old and new suspicious log formats."""

    suspicious_markers = [
        "prompt injection detected",
        "suspicious input detected"
    ]

    log_lower = log.lower()

    return any(
        marker in log_lower
        for marker in suspicious_markers
    )


# ==========================================
# RISK SCORE EXTRACTION
# ==========================================

def extract_risk_score(log):
    """Extract risk score from different log formats."""

    patterns = [

        r"Risk\s*:\s*(\d+)",

        r"risk_score\s*=\s*(\d+)",

        r"score\s*=\s*(\d+)"
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            log,
            re.IGNORECASE
        )

        if match:

            return int(match.group(1))

    return None


# ==========================================
# SEVERITY CLASSIFICATION
# ==========================================

def extract_severity(log, risk_score):
    """Extract severity or calculate it from risk score."""

    match = re.search(
        r"Severity\s*:\s*(HIGH|MEDIUM|LOW)",
        log,
        re.IGNORECASE
    )

    if match:

        return match.group(1).upper()

    if risk_score is None:

        return "UNKNOWN"

    if risk_score >= HIGH_RISK_THRESHOLD:

        return "HIGH"

    if risk_score >= MEDIUM_RISK_THRESHOLD:

        return "MEDIUM"

    return "LOW"


# ==========================================
# CATEGORY EXTRACTION
# ==========================================

def extract_categories(log):
    """Extract security categories from the log."""

    categories = []

    category_pattern = (
        r"categories\s*=\s*\[(.*?)\]"
    )

    match = re.search(
        category_pattern,
        log,
        re.IGNORECASE
    )

    if match:

        category_text = match.group(1)

        categories = re.findall(
            r"['\"]([^'\"]+)['\"]",
            category_text
        )

    # Extract categories from the newer Patterns format.

    if not categories:

        for category in ATTACK_MAPPING:

            if category in log:

                categories.append(category)

    # Support older matched_phrases logs.

    if not categories:

        log_lower = log.lower()

        if "ignore previous instructions" in log_lower:

            categories.append(
                "instruction_override"
            )

        if (
            "reveal confidential information" in log_lower
            or "reveal the system prompt" in log_lower
            or "show me your hidden instructions" in log_lower
            or "disclose protected data" in log_lower
        ):

            categories.append(
                "data_exfiltration"
            )

        if (
            "bypass security" in log_lower
            or "disable safety" in log_lower
            or "override security controls" in log_lower
        ):

            categories.append(
                "security_bypass"
            )

    return list(dict.fromkeys(categories))


# ==========================================
# ATTACK MAPPING
# ==========================================

def map_attack_behavior(categories):
    """Map detected categories to security behaviors."""

    mapped_attacks = []

    for category in categories:

        mapping = ATTACK_MAPPING.get(category)

        if mapping:

            mapped_attacks.append({
                "category": category,
                "behavior": mapping["behavior"],
                "description": mapping["description"],
                "framework": mapping["framework"],
                "technique": mapping["technique"]
            })

    return mapped_attacks


# ==========================================
# LOG DETAILS
# ==========================================

def extract_details(log):
    """Extract log message without timestamp."""

    match = re.match(
        r"^\d{4}-\d{2}-\d{2} "
        r"\d{2}:\d{2}:\d{2}\s*-\s*",
        log
    )

    if match:

        return log[match.end():].strip()

    return log.strip()


# ==========================================
# SECURITY LOG ANALYSIS
# ==========================================

def analyze_security_logs(logs):
    """Analyze security logs and map attack behaviors."""

    total_events = len(logs)

    suspicious_events = 0
    normal_events = 0

    severity_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0
    }

    recent_suspicious_events = []

    parsed_events = []

    for log in logs:

        timestamp = extract_timestamp(log)

        details = extract_details(log)

        suspicious = is_suspicious_log(log)

        risk_score = None

        severity = "N/A"

        categories = []

        mapped_attacks = []

        if suspicious:

            suspicious_events += 1

            risk_score = extract_risk_score(log)

            severity = extract_severity(
                log,
                risk_score
            )

            categories = extract_categories(log)

            mapped_attacks = map_attack_behavior(
                categories
            )

            severity_counts[severity] += 1

            event_type = "SUSPICIOUS"

            recent_suspicious_events.append({

                "timestamp": timestamp,

                "severity": severity,

                "risk_score": risk_score,

                "categories": categories,

                "mapped_attacks": mapped_attacks,

                "details": details

            })

        else:

            normal_events += 1

            event_type = "NORMAL"

        parsed_events.append({

            "timestamp": timestamp,

            "event_type": event_type,

            "severity": severity,

            "risk_score": risk_score,

            "categories": categories,

            "mapped_attacks": mapped_attacks,

            "details": details

        })

    detection_rate = (

        suspicious_events / total_events * 100

        if total_events > 0

        else 0

    )

    severity_percentages = {}

    for severity, count in severity_counts.items():

        severity_percentages[severity] = (

            count / suspicious_events * 100

            if suspicious_events > 0

            else 0

        )

    return {

        "total_events": total_events,

        "suspicious_events": suspicious_events,

        "normal_events": normal_events,

        "detection_rate": detection_rate,

        "severity_counts": severity_counts,

        "severity_percentages": severity_percentages,

        "recent_suspicious_events": (
            recent_suspicious_events[-RECENT_EVENT_LIMIT:]
        ),

        "parsed_events": parsed_events

    }


# ==========================================
# CSV EXPORT
# ==========================================

def export_csv_report(report):
    """Export security events and attack mappings to CSV."""

    fieldnames = [

        "report_generated",

        "timestamp",

        "event_type",

        "severity",

        "risk_score",

        "categories",

        "attack_behavior",

        "framework",

        "technique",

        "details"

    ]

    report_generated = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with open(
        CSV_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for event in report["parsed_events"]:

            mapped_attacks = event["mapped_attacks"]

            attack_behavior = "; ".join(
                attack["behavior"]
                for attack in mapped_attacks
            )

            frameworks = "; ".join(
                attack["framework"]
                for attack in mapped_attacks
            )

            techniques = "; ".join(
                attack["technique"]
                for attack in mapped_attacks
            )

            writer.writerow({

                "report_generated": report_generated,

                "timestamp": event["timestamp"],

                "event_type": event["event_type"],

                "severity": event["severity"],

                "risk_score": (
                    event["risk_score"]
                    if event["risk_score"] is not None
                    else ""
                ),

                "categories": "; ".join(
                    event["categories"]
                ),

                "attack_behavior": attack_behavior,

                "framework": frameworks,

                "technique": techniques,

                "details": event["details"]

            })

    print(
        f"\nCSV report created: {CSV_FILE}"
    )

    print(
        f"Total events exported: "
        f"{len(report['parsed_events'])}"
    )


# ==========================================
# SECURITY REPORT
# ==========================================

def generate_security_report():
    """Generate console security report and CSV."""

    logs = read_security_logs()

    if not logs:

        print("No security logs available.")

        return

    report = analyze_security_logs(logs)

    print("\n" + "=" * 55)

    print("              SOC SECURITY REPORT")

    print("=" * 55)

    print(
        f"Total log entries: "
        f"{report['total_events']}"
    )

    print(
        f"Suspicious events: "
        f"{report['suspicious_events']}"
    )

    print(
        f"Normal events: "
        f"{report['normal_events']}"
    )

    print(
        f"Suspicious log rate: "
        f"{report['detection_rate']:.2f}%"
    )

    print("\nSeverity Breakdown")

    print("-" * 35)

    for severity, count in report[
        "severity_counts"
    ].items():

        percentage = report[
            "severity_percentages"
        ][severity]

        print(
            f"{severity}: {count} "
            f"({percentage:.2f}%)"
        )

    print("\nRecent Suspicious Events")

    print("-" * 35)

    recent_events = report[
        "recent_suspicious_events"
    ]

    if not recent_events:

        print("No suspicious events found.")

    else:

        for event in recent_events:

            print(
                f"\nTimestamp: {event['timestamp']}"
            )

            print(
                f"Severity: {event['severity']}"
            )

            print(
                f"Risk Score: "
                f"{event['risk_score']}"
            )

            print(
                f"Categories: "
                f"{', '.join(event['categories'])}"
            )

            print("Attack Behavior:")

            if event["mapped_attacks"]:

                for attack in event["mapped_attacks"]:

                    print(
                        f"  - {attack['behavior']}"
                    )

                    print(
                        f"    Framework: "
                        f"{attack['framework']}"
                    )

                    print(
                        f"    Technique: "
                        f"{attack['technique']}"
                    )

                    print(
                        f"    Description: "
                        f"{attack['description']}"
                    )

            else:

                print(
                    "  No category mapping available"
                )

            print(
                f"Details: {event['details']}"
            )

    print("\nSecurity Status")

    print("-" * 35)

    if report["suspicious_events"] > 0:

        print(
            "WARNING: Suspicious activity "
            "detected in security logs."
        )

    else:

        print(
            "INFO: No known suspicious "
            "activity detected."
        )

    export_csv_report(report)


# ==========================================
# MAIN
# ==========================================

if __name__ == "__main__":

    generate_security_report()
