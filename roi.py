"""First-year ROI for the illustrative TechnoProfi scenario, in RUB."""

incident_savings = 4 * 1_000_000 - 2 * 1_000_000
downtime_before, downtime_after = 20, 10
downtime_savings = (downtime_before - downtime_after) * 50_000
leak_savings = 1_000_000 - 500_000
cost = 450_000 + 200_000
gross = incident_savings + downtime_savings + leak_savings
net = gross - cost

print(f"Incident response savings: {incident_savings:,} RUB")
print(f"Downtime savings: {downtime_savings:,} RUB")
print(f"Data breach loss reduction: {leak_savings:,} RUB")
print(f"First-year cost: {cost:,} RUB")
print(f"Gross annual benefit: {gross:,} RUB")
print(f"Net annual benefit: {net:,} RUB")
print(f"Availability: {1 - downtime_before / 8760:.4%} -> "
      f"{1 - downtime_after / 8760:.4%}")
print(f"First-year ROI: {net / cost:.2%}")
