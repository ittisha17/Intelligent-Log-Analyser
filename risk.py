def calculate_risk(threats):
    for t in threats:
        score = t["count"]

        if score > 50:
            t["risk"] = "High"
        elif score > 10:
            t["risk"] = "Medium"
        else:
            t["risk"] = "Low"

    return threats