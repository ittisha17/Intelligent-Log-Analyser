def generate_report(df):
    if df.empty:
        return "No threats found."

    report = "=== SECURITY REPORT ===\n\n"

    high = df[df["risk"] == "High"]
    medium = df[df["risk"] == "Medium"]

    report += f"Total Threats: {len(df)}\n"
    report += f"High Risk: {len(high)}\n"
    report += f"Medium Risk: {len(medium)}\n\n"

    report += "Top Threats:\n"
    for _, row in df.iterrows():
        report += f"- {row['ip']} → {row['attack']} ({row['risk']})\n"

    report += "\nRecommendations:\n"
    report += "- Enable rate limiting\n"
    report += "- Use strong authentication\n"
    report += "- Monitor sensitive endpoints\n"

    return report