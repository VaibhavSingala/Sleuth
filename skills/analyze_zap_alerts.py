import json
from typing import List, Dict, Any

def analyze_zap_alerts(url: str) -> str:
    """
    Reads raw alerts from OWASP ZAP for a given URL and provides a structured, 
    human-readable executive summary report.

    Args:
        url (str): The base URL to check alerts against (e.g., "http://example.com").

    Returns:
        str: A formatted string containing the alert summary.
    """
    try:
        # 1. Call the existing ZAP tool
        alerts_data = zap_alerts(url=url)
        
        if not alerts_data or isinstance(alerts_data, str) and "No alerts found" in alerts_data:
            return f"✅ **ZAP Alert Analysis for {url}:**\n\n🎉 No security alerts were found by OWASP ZAP! The site appears clean based on this scan."

        # Assuming zap_alerts returns a string that is JSON formatted, or the raw list/dict structure.
        if isinstance(alerts_data, str):
            try:
                alerts = json.loads(alerts_data)
            except json.JSONDecodeError:
                # If it's just a nicely formatted string, we might need to parse it differently, 
                # but for robustness, let's assume the tool returns JSON structure if possible.
                return f"⚠️ **ZAP Alert Analysis for {url}:**\n\nCould not perfectly parse raw output from ZAP. Here is the raw summary:\n---\n{alerts_data}"
        else:
            alerts = alerts_data

        # 2. Process and categorize alerts
        categorized_alerts: Dict[str, List[Dict[str, Any]]] = {
            "Critical": [],
            "High": [],
            "Medium": [],
            "Low": []
        }
        total_alerts = len(alerts)

        for alert in alerts:
            severity = alert.get("risk", "Info") # ZAP often uses 'risk' field for severity mapping
            if severity not in categorized_alerts:
                # Handle cases where risk might be something else (e.g., "Informational")
                categorized_alerts[f"{severity}"] = []

            alert_info = {
                "Name": alert.get("name", "N/A"),
                "Confidence": alert.get("confidence", "N/A"),
                "Description": alert.get("desc", "No description provided.")[:80] + "..."
            }
            categorized_alerts[severity].append(alert_info)

        # 3. Generate Report
        report = f"🛡️ **ZAP Security Alert Analysis Report for {url}** 🛡️\n"
        report += f"===================================================\n"
        report += f"📊 **Total Alerts Found:** {total_alerts}\n\n"

        for severity, alerts_list in categorized_alerts.items():
            count = len(alerts_list)
            report += f"🚨 **{severity} Severity ({count}):**\n"
            if count > 0:
                for i, alert in enumerate(alerts_list):
                    report += f"  - [{i+1}] {alert['Name']} (Confidence: {alert['Confidence']})\n"
                    report += f"    > *Summary:* {alert['Description']}\n"
            else:
                report += "  - None found.\n"
            report += "\n"

        # 4. Add quick remediation advice
        if total_alerts > 0:
            report += "💡 **Quick Remediation Advice:**\n"
            report += "   * **Critical/High:** Prioritize fixing these immediately. Ensure proper input validation and output encoding.\n"
            report += "   * **Medium/Low:** Address these in the next sprint to improve overall security posture."

        return report

    except Exception as e:
        return f"❌ **Error during ZAP Alert Analysis for {url}:** An unexpected error occurred. Details: {e}"