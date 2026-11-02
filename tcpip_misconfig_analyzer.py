#python --version
#python -m venv venv
#venv\Scripts\activate
#pip install scapy
#mkdir reports
#python tcpip_misconfig_analyzer.py
import json
import os
import statistics
import time
from datetime import datetime

from scapy.all import IP, ICMP, TCP, RandShort, sr1, conf

# Reduce noisy Scapy output
conf.verb = 0

PROJECT_TITLE = "Analysis of TCP/IP Stack Misconfigurations using Active Probing"

PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    8080: "HTTP-Alt",
}


def get_service_name(port):
    return PORT_SERVICES.get(port, "Unknown")


def guess_os_from_ttl(ttl):
    if ttl is None:
        return "Unknown"
    if ttl <= 64:
        return "Linux/Unix-based system (likely)"
    if ttl <= 128:
        return "Windows-based system (likely)"
    return "Network device / custom stack / unknown"


def safe_flag_string(tcp_layer):
    try:
        return str(tcp_layer.flags)
    except Exception:
        return "UNKNOWN"


def get_ip_header_fields(reply):
    ttl = None
    ipid = None
    if reply and reply.haslayer(IP):
        ttl = reply[IP].ttl
        ipid = reply[IP].id
    return ttl, ipid


def tcp_syn_probe(target, port, timeout=2):
    result = {
        "probe_type": "TCP_SYN",
        "port": port,
        "service": get_service_name(port),
        "status": "unknown",
        "flags": None,
        "ttl": None,
        "ipid": None,
        "response_summary": "No response",
    }

    try:
        packet = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags="S")
        reply = sr1(packet, timeout=timeout)

        if reply is None:
            result["status"] = "filtered_or_no_response"
            result["response_summary"] = "No response received"
            return result

        ttl, ipid = get_ip_header_fields(reply)
        result["ttl"] = ttl
        result["ipid"] = ipid

        if reply.haslayer(TCP):
            flags = safe_flag_string(reply[TCP])
            result["flags"] = flags

            if "SA" in flags:
                result["status"] = "open"
                result["response_summary"] = "SYN-ACK received"
            elif "RA" in flags or flags == "R":
                result["status"] = "closed"
                result["response_summary"] = "RST received"
            else:
                result["status"] = "unexpected_tcp_response"
                result["response_summary"] = f"Unexpected TCP flags: {flags}"

        elif reply.haslayer(ICMP):
            result["status"] = "icmp_response"
            result["response_summary"] = "ICMP response received instead of TCP"
        else:
            result["status"] = "unknown_response"
            result["response_summary"] = "Unknown response type"

    except PermissionError:
        result["status"] = "error"
        result["response_summary"] = "Permission denied. Run VS Code as Administrator."
    except Exception as e:
        result["status"] = "error"
        result["response_summary"] = f"Error: {str(e)}"

    return result


def tcp_ack_probe(target, port, timeout=2):
    result = {
        "probe_type": "TCP_ACK",
        "port": port,
        "service": get_service_name(port),
        "status": "unknown",
        "flags": None,
        "ttl": None,
        "ipid": None,
        "response_summary": "No response",
    }

    try:
        packet = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags="A")
        reply = sr1(packet, timeout=timeout)

        if reply is None:
            result["status"] = "filtered_or_no_response"
            result["response_summary"] = "No response received"
            return result

        ttl, ipid = get_ip_header_fields(reply)
        result["ttl"] = ttl
        result["ipid"] = ipid

        if reply.haslayer(TCP):
            flags = safe_flag_string(reply[TCP])
            result["flags"] = flags

            if "R" in flags:
                result["status"] = "unfiltered_reachable"
                result["response_summary"] = "RST received, host reachable / likely unfiltered"
            else:
                result["status"] = "unexpected_tcp_response"
                result["response_summary"] = f"Unexpected TCP flags: {flags}"

        elif reply.haslayer(ICMP):
            result["status"] = "icmp_response"
            result["response_summary"] = "ICMP response received"
        else:
            result["status"] = "unknown_response"
            result["response_summary"] = "Unknown response type"

    except PermissionError:
        result["status"] = "error"
        result["response_summary"] = "Permission denied. Run VS Code as Administrator."
    except Exception as e:
        result["status"] = "error"
        result["response_summary"] = f"Error: {str(e)}"

    return result


def icmp_probe(target, timeout=2):
    result = {
        "probe_type": "ICMP_ECHO",
        "status": "unknown",
        "ttl": None,
        "ipid": None,
        "round_trip_ms": None,
        "response_summary": "No response",
    }

    try:
        packet = IP(dst=target) / ICMP()
        start = time.time()
        reply = sr1(packet, timeout=timeout)
        end = time.time()

        if reply is None:
            result["status"] = "no_reply"
            result["response_summary"] = "No ICMP echo reply received"
            return result

        ttl, ipid = get_ip_header_fields(reply)
        result["ttl"] = ttl
        result["ipid"] = ipid
        result["round_trip_ms"] = round((end - start) * 1000, 2)

        if reply.haslayer(ICMP):
            icmp_type = reply[ICMP].type
            icmp_code = reply[ICMP].code

            if icmp_type == 0:
                result["status"] = "reachable"
                result["response_summary"] = "ICMP echo reply received"
            else:
                result["status"] = "icmp_non_echo_reply"
                result["response_summary"] = f"ICMP type={icmp_type}, code={icmp_code}"
        else:
            result["status"] = "unexpected_response"
            result["response_summary"] = "Non-ICMP response to ICMP probe"

    except PermissionError:
        result["status"] = "error"
        result["response_summary"] = "Permission denied. Run VS Code as Administrator."
    except Exception as e:
        result["status"] = "error"
        result["response_summary"] = f"Error: {str(e)}"

    return result


def repeated_icmp_analysis(target, count=3, timeout=2):
    ttl_values = []
    ipid_values = []
    rtts = []
    raw_results = []

    for _ in range(count):
        result = icmp_probe(target, timeout=timeout)
        raw_results.append(result)

        if result["ttl"] is not None:
            ttl_values.append(result["ttl"])
        if result["ipid"] is not None:
            ipid_values.append(result["ipid"])
        if result["round_trip_ms"] is not None:
            rtts.append(result["round_trip_ms"])

        time.sleep(0.5)

    analysis = {
        "probe_type": "REPEATED_ICMP_ANALYSIS",
        "count": count,
        "ttl_values": ttl_values,
        "ipid_values": ipid_values,
        "rtts_ms": rtts,
        "avg_rtt_ms": round(statistics.mean(rtts), 2) if rtts else None,
        "ttl_stable": len(set(ttl_values)) == 1 if ttl_values else False,
        "ipid_predictable": False,
        "summary": "",
        "raw_results": raw_results,
        "os_guess": guess_os_from_ttl(ttl_values[0]) if ttl_values else "Unknown",
    }

    if len(ipid_values) >= 2:
        diffs = [ipid_values[i + 1] - ipid_values[i] for i in range(len(ipid_values) - 1)]
        if len(set(diffs)) == 1:
            analysis["ipid_predictable"] = True

    summary_parts = []
    if ttl_values:
        summary_parts.append(f"TTL values observed: {ttl_values}")
    if ipid_values:
        summary_parts.append(f"IPID values observed: {ipid_values}")
    if analysis["avg_rtt_ms"] is not None:
        summary_parts.append(f"Average RTT: {analysis['avg_rtt_ms']} ms")
    if analysis["ttl_stable"]:
        summary_parts.append("TTL remained stable across repeated probes")
    if analysis["ipid_predictable"]:
        summary_parts.append("IPID pattern appears predictable")
    if analysis["os_guess"] != "Unknown":
        summary_parts.append(f"Estimated OS from TTL: {analysis['os_guess']}")

    analysis["summary"] = "; ".join(summary_parts) if summary_parts else "No repeated probe data available"
    return analysis


def analyze_results(target, syn_results, ack_results, icmp_result, repeat_analysis):
    findings = []

    open_ports = [r["port"] for r in syn_results if r["status"] == "open"]
    closed_ports = [r["port"] for r in syn_results if r["status"] == "closed"]
    filtered_ports = [r["port"] for r in syn_results if r["status"] == "filtered_or_no_response"]

    open_port_services = [f"{r['port']} ({r['service']})" for r in syn_results if r["status"] == "open"]
    closed_port_services = [f"{r['port']} ({r['service']})" for r in syn_results if r["status"] == "closed"]
    filtered_port_services = [f"{r['port']} ({r['service']})" for r in syn_results if r["status"] == "filtered_or_no_response"]

    if open_port_services:
        findings.append(f"Open TCP ports detected: {open_port_services}")

    if closed_port_services:
        findings.append(f"Closed TCP ports detected: {closed_port_services}")

    if filtered_port_services:
        findings.append(f"Filtered or non-responsive TCP ports: {filtered_port_services}")

    if icmp_result["status"] == "reachable":
        findings.append("ICMP echo replies are enabled")
    elif icmp_result["status"] == "no_reply":
        findings.append("ICMP echo replies are blocked or the host did not respond")

    unfiltered_ack_ports = [r["port"] for r in ack_results if r["status"] == "unfiltered_reachable"]
    unfiltered_ack_port_services = [
        f"{r['port']} ({r['service']})" for r in ack_results if r["status"] == "unfiltered_reachable"
    ]
    if unfiltered_ack_port_services:
        findings.append(
            f"ACK probe received RST on ports {unfiltered_ack_port_services}, suggesting reachable/unfiltered behavior"
        )

    if repeat_analysis["ttl_stable"]:
        findings.append("Stable TTL values observed in repeated probes")

    if repeat_analysis["ipid_predictable"]:
        findings.append("Predictable IPID progression observed")

    if repeat_analysis["os_guess"] != "Unknown":
        findings.append(f"Estimated target OS: {repeat_analysis['os_guess']}")

    if not findings:
        findings.append("No strong conclusions could be drawn from the probes")

    detailed_assessment = []

    if len(open_ports) >= 2:
        detailed_assessment.append("Multiple service ports appear exposed")
    elif len(open_ports) == 1:
        detailed_assessment.append("At least one service port appears exposed")

    if icmp_result["status"] == "reachable":
        detailed_assessment.append("Target responds to ICMP echo requests")

    if len(unfiltered_ack_ports) >= 2:
        detailed_assessment.append("Target appears to allow unsolicited ACK-based reachability responses")

    if repeat_analysis["ipid_predictable"]:
        detailed_assessment.append("Reply header behavior may be useful for fingerprinting")

    if repeat_analysis["os_guess"] != "Unknown":
        detailed_assessment.append(f"TTL-based operating system estimate: {repeat_analysis['os_guess']}")

    risk_summary_parts = []
    if icmp_result["status"] == "reachable":
        risk_summary_parts.append("ICMP responsiveness")
    if len(unfiltered_ack_ports) >= 1:
        risk_summary_parts.append("limited ACK filtering")
    if repeat_analysis["ipid_predictable"]:
        risk_summary_parts.append("predictable IPID behavior")
    if len(open_ports) >= 1:
        risk_summary_parts.append("service exposure")

    if risk_summary_parts:
        risk_summary = "The system shows exposure indicators due to " + ", ".join(risk_summary_parts) + "."
    else:
        risk_summary = "The system shows limited exposure based on the tested probes."

    return {
        "target": target,
        "findings": findings,
        "detailed_assessment": detailed_assessment,
        "risk_summary": risk_summary,
        "open_ports": open_ports,
        "closed_ports": closed_ports,
        "filtered_ports": filtered_ports,
        "os_guess": repeat_analysis["os_guess"],
        "score_explanation": (
            "Score is based on exposed services, ICMP availability, ACK filtering behavior, "
            "and predictability of IP stack fields such as IPID."
        ),
    }


def calculate_score(analysis, ack_results, icmp_result, repeat_analysis):
    score = 10
    reasons = []

    open_ports = analysis["open_ports"]

    high_value_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]
    for port in open_ports:
        if port in high_value_ports:
            score -= 1
            reasons.append(f"Port {port} ({get_service_name(port)}) is open")

    if icmp_result["status"] == "reachable":
        score -= 1
        reasons.append("ICMP echo replies are enabled")

    unfiltered_ack_count = sum(1 for r in ack_results if r["status"] == "unfiltered_reachable")
    if unfiltered_ack_count >= 1:
        score -= 1
        reasons.append("ACK probe indicates reachable/unfiltered behavior")

    if unfiltered_ack_count >= 2:
        score -= 1
        reasons.append("Multiple ACK probes indicate limited filtering")

    if repeat_analysis["ipid_predictable"]:
        score -= 2
        reasons.append("Predictable IPID behavior observed")

    if len(open_ports) >= 2:
        score -= 2
        reasons.append("Multiple open service ports observed")

    score = max(score, 0)

    if score >= 8:
        risk = "Low"
    elif score >= 5:
        risk = "Medium"
    else:
        risk = "High"

    return {
        "score_out_of_10": score,
        "risk_level": risk,
        "score_reasons": reasons,
        "explanation": (
            "This heuristic score estimates TCP/IP stack exposure based on service exposure, "
            "ICMP responsiveness, unsolicited ACK behavior, and predictable reply characteristics."
        ),
    }


def generate_mitigations(analysis, ack_results, icmp_result, repeat_analysis):
    mitigations = []

    if icmp_result["status"] == "reachable":
        mitigations.append({
            "issue": "ICMP echo replies enabled",
            "solution": "Restrict unnecessary ICMP echo replies using host firewall or network firewall rules."
        })

    if analysis["open_ports"]:
        mitigations.append({
            "issue": "Open service ports detected",
            "solution": "Close unused ports, disable unnecessary services, and allow access only to required users through firewall rules."
        })

    unfiltered_ack_count = sum(1 for r in ack_results if r["status"] == "unfiltered_reachable")
    if unfiltered_ack_count >= 1:
        mitigations.append({
            "issue": "Unsolicited ACK packets receive responses",
            "solution": "Implement stricter stateful firewall filtering to drop unexpected ACK packets."
        })

    if repeat_analysis["ipid_predictable"]:
        mitigations.append({
            "issue": "Predictable IPID behavior",
            "solution": "Use a modern TCP/IP stack, keep the operating system updated, and enable networking protections that reduce fingerprinting."
        })

    if repeat_analysis["ttl_stable"]:
        mitigations.append({
            "issue": "Stable TTL behavior may help fingerprinting",
            "solution": "Use firewall normalization, proxying, or network-layer hardening where appropriate to reduce fingerprinting accuracy."
        })

    if analysis["os_guess"] != "Unknown":
        mitigations.append({
            "issue": "Possible OS fingerprinting through reply characteristics",
            "solution": "Reduce information leakage by limiting unnecessary responses and keeping the host patched and firewall-hardened."
        })

    if not mitigations:
        mitigations.append({
            "issue": "No major exposure indicators detected",
            "solution": "Maintain current configuration, keep monitoring, and apply regular security updates."
        })

    return mitigations


def generate_reports(target, syn_results, ack_results, icmp_result, repeat_analysis, analysis, score_data, mitigations):
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target_name = target.replace(".", "_").replace(":", "_")
    base_name = f"report_{safe_target_name}_{timestamp}"

    json_path = os.path.join("reports", base_name + ".json")
    txt_path = os.path.join("reports", base_name + ".txt")

    full_data = {
        "project": PROJECT_TITLE,
        "generated_at": datetime.now().isoformat(),
        "target": target,
        "tcp_syn_results": syn_results,
        "tcp_ack_results": ack_results,
        "icmp_result": icmp_result,
        "repeated_probe_analysis": repeat_analysis,
        "analysis": analysis,
        "score": score_data,
        "mitigations": mitigations,
    }

    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(full_data, jf, indent=4)

    lines = []
    lines.append(PROJECT_TITLE)
    lines.append("=" * 70)
    lines.append(f"Generated At: {datetime.now().isoformat()}")
    lines.append(f"Target: {target}")
    lines.append("")

    lines.append("1. TCP SYN Probe Results")
    lines.append("-" * 30)
    for r in syn_results:
        lines.append(
            f"Port {r['port']} ({r['service']}): Status={r['status']}, Flags={r['flags']}, "
            f"TTL={r['ttl']}, IPID={r['ipid']}, Summary={r['response_summary']}"
        )
    lines.append("")

    lines.append("2. TCP ACK Probe Results")
    lines.append("-" * 30)
    for r in ack_results:
        lines.append(
            f"Port {r['port']} ({r['service']}): Status={r['status']}, Flags={r['flags']}, "
            f"TTL={r['ttl']}, IPID={r['ipid']}, Summary={r['response_summary']}"
        )
    lines.append("")

    lines.append("3. ICMP Probe Result")
    lines.append("-" * 30)
    lines.append(
        f"Status={icmp_result['status']}, RTT={icmp_result['round_trip_ms']} ms, "
        f"TTL={icmp_result['ttl']}, IPID={icmp_result['ipid']}, Summary={icmp_result['response_summary']}"
    )
    lines.append("")

    lines.append("4. Repeated Probe Analysis")
    lines.append("-" * 30)
    lines.append(repeat_analysis["summary"])
    lines.append("")

    lines.append("5. Findings")
    lines.append("-" * 30)
    for f in analysis["findings"]:
        lines.append(f"- {f}")
    lines.append("")

    lines.append("6. Detailed Assessment")
    lines.append("-" * 30)
    if analysis["detailed_assessment"]:
        for d in analysis["detailed_assessment"]:
            lines.append(f"- {d}")
    else:
        lines.append("- No additional assessment")
    lines.append("")

    lines.append("7. Risk Summary")
    lines.append("-" * 30)
    lines.append(analysis["risk_summary"])
    lines.append("")

    lines.append("8. Mitigation Recommendations")
    lines.append("-" * 30)
    for m in mitigations:
        lines.append(f"Issue: {m['issue']}")
        lines.append(f"Recommended Fix: {m['solution']}")
        lines.append("")
    
    lines.append("9. Score")
    lines.append("-" * 30)
    lines.append(f"Score: {score_data['score_out_of_10']}/10")
    lines.append(f"Risk Level: {score_data['risk_level']}")
    lines.append(f"Scoring Method: {score_data['explanation']}")
    lines.append("Reasons:")
    if score_data["score_reasons"]:
        for reason in score_data["score_reasons"]:
            lines.append(f"- {reason}")
    else:
        lines.append("- No deductions applied")
    lines.append("")
    lines.append(f"Assessment Logic: {analysis['score_explanation']}")

    with open(txt_path, "w", encoding="utf-8") as tf:
        tf.write("\n".join(lines))

    return json_path, txt_path


def print_section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def main():
    print_section("TCP/IP STACK MISCONFIGURATION ANALYZER")
    print("Use only on systems you own or are authorized to test.\n")

    target = input("Enter target IP address: ").strip()

    if not target:
        print("No target entered. Exiting.")
        return

    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]

    print_section("Running TCP SYN probes")
    syn_results = []
    for port in common_ports:
        result = tcp_syn_probe(target, port)
        syn_results.append(result)
        print(f"[SYN] Port {port} ({result['service']}): {result['status']} | {result['response_summary']}")

    print_section("Running TCP ACK probes")
    ack_results = []
    for port in common_ports:
        result = tcp_ack_probe(target, port)
        ack_results.append(result)
        print(f"[ACK] Port {port} ({result['service']}): {result['status']} | {result['response_summary']}")

    print_section("Running ICMP probe")
    icmp_result = icmp_probe(target)
    print(f"[ICMP] {icmp_result['status']} | {icmp_result['response_summary']}")

    print_section("Running repeated ICMP analysis")
    repeat_analysis = repeated_icmp_analysis(target, count=3)
    print(repeat_analysis["summary"])

    print_section("Analyzing results")
    analysis = analyze_results(target, syn_results, ack_results, icmp_result, repeat_analysis)
    for finding in analysis["findings"]:
        print(f"- {finding}")

    print_section("Calculating score")
    score_data = calculate_score(analysis, ack_results, icmp_result, repeat_analysis)
    print(f"Score: {score_data['score_out_of_10']}/10")
    print(f"Risk Level: {score_data['risk_level']}")

    mitigations = generate_mitigations(analysis, ack_results, icmp_result, repeat_analysis)

    print_section("Mitigation Recommendations")
    for m in mitigations:
        print(f"- Issue: {m['issue']}")
        print(f"  Fix: {m['solution']}")

    print_section("Generating reports")
    json_path, txt_path = generate_reports(
        target,
        syn_results,
        ack_results,
        icmp_result,
        repeat_analysis,
        analysis,
        score_data,
        mitigations,
    )
    print(f"JSON report saved to: {json_path}")
    print(f"Text report saved to: {txt_path}")

    print_section("Done")


if __name__ == "__main__":
    main()