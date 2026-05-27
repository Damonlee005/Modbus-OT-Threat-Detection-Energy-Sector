# Threat Assessment Report
## Modbus TCP Anomaly Detection — Power Grid OT Environments
**Author:** Damon Golliher
**Date:** May 2026
**Course Context:** Applied Cybersecurity — University of Tennessee, Knoxville

---

## Background

This project came out of packet analysis work in CYBR 202 at
the University of Tennessee. Spending time in Wireshark going
through real traffic captures made me curious about what
malicious traffic actually looks like compared to normal
traffic and whether you could build something that flags it
automatically. The configuration auditing work I did in that
class also pushed me toward thinking about how security
controls fail in practice and what it takes to actually
detect those failures rather than just document them.

Outside of coursework I have been reading into ICS and OT
security for a while. Critical infrastructure security sits
at the intersection of two things I find genuinely interesting,
the technical side of how these protocols and systems work
and the real world consequences when they do not. Most IT
security problems result in data loss or downtime. OT security
problems can result in physical damage, equipment failure, and
in the worst cases direct harm to people. That asymmetry is
what makes it worth understanding deeply.

Reading about the 2015 Ukraine power grid attack pushed me
toward Modbus TCP specifically. The attackers moved through
industrial control systems without triggering anything and
part of the reason that worked is because Modbus has no
authentication built into it. Any device on the same network
can send commands directly to a PLC with no credential
requirement. That gap felt like the right problem to work on
and this project is my first serious attempt at building
something that addresses it.

This report covers what I built, how it works, what the
results showed, and what those results mean for the kind
of environments this traffic comes from.

---

## What I Built and How

The core idea was that normal Modbus TCP traffic has a
predictable rhythm and attacks break that rhythm in ways
you can measure. I used PyShark to parse raw PCAP files
and pull out per-packet features: function code, transaction
ID, packet length, and source IP. From those I calculated
four behavioral features, inter-packet timing, packet
length deviation from a rolling average, and function code
frequency per source IP.

I trained an Isolation Forest model on clean baseline
traffic. Isolation Forest works by building random decision
trees and measuring how quickly each point gets separated
from the rest of the data. Anomalies get isolated faster
because they are statistically different from everything
around them. Anything that scores below the threshold
gets flagged. I set the contamination rate at 5 percent
based on the expected ratio of attack to normal traffic
across the full dataset.

---

## Data Sources

**ICS-PCAPS — University of Coimbra CyberSec Team**
Labeled Modbus TCP traffic published alongside a paper at
CRITIS 2018. Contains six attack categories: Modbus query
flooding, a second flooding variation, man-in-the-middle
manipulation, TCP SYN flood, ping flood, and clean baseline
traffic. The labeled categories made it possible to check
whether the model was actually flagging the right things.

Citation: Frazao et al., "Denial of Service Attacks:
Detecting the frailties of machine learning algorithms
in the Classification Process," CRITIS 2018, Springer.
DOI: 10.1007/978-3-030-05849-4_19

**4SICS GeekLounge ICS Traffic Captures**
Real ICS network traffic captured at the 4SICS industrial
cybersecurity conference in Stockholm, 2015. Used to add
real world ICS traffic context alongside the labeled
attack data.

---

## Attack Scenarios

| Scenario | Protocol | MITRE Technique | MITRE ID |
|---|---|---|---|
| Unauthorized register write | Modbus FC 6 | Unauthorized Command Message | T0855 |
| Force single coil injection | Modbus FC 5 | Unauthorized Command Message | T0855 |
| Read coil reconnaissance | Modbus FC 1 | Modify Parameter | T0836 |
| Read input reconnaissance | Modbus FC 2 | Modify Parameter | T0836 |
| Bulk register write | Modbus FC 16 | Program Download | T0843 |
| Mass coil manipulation | Modbus FC 15 | Program Download | T0843 |
| Device fingerprinting | Modbus FC 17 | Program Upload | T0845 |
| Unauthorized file read | Modbus FC 20 | Point & Tag Identification | T0861 |
| Diagnostic channel abuse | Modbus FC 43 | Spoof Reporting Message | T0856 |
| Modbus query flooding | Modbus TCP | Denial of Service | T0814 |
| Man-in-the-middle manipulation | Modbus TCP | Adversary-in-the-Middle | T0830 |
| TCP SYN flood | TCP | Denial of Service | T0814 |
| Ping flood DDoS | ICMP | Denial of Service | T0814 |
| Baseline deviation | Modbus TCP | Anomalous Behavior | T0802 |

---

## What I Found

The flooding attacks were the clearest to detect. Modbus
query flooding hammers the network with repeated requests
and that shows up immediately in the inter-packet timing
and function code frequency features. Normal polling is
consistent and spaced out. Flooding traffic is not. The
model flagged those captures without much trouble.

Man-in-the-middle was more interesting. The timing was
not as disrupted but the packet length deviation feature
picked up modifications being made to packet content
mid-stream. That was not something I fully expected going
in. It showed that having multiple features matters because
some attacks show up in timing and others show up in content.

The baseline traffic produced false positives close to the
5 percent rate I set which was a good sign. The model was
not just flagging everything and the threshold was roughly
calibrated correctly.

After mapping to MITRE ATT&CK for ICS the largest clusters
landed under T0855 Unauthorized Command Message and T0814
Denial of Service which lines up with what the labeled
attack categories would predict.

---

## Why This Matters

Modbus has no authentication. There is nothing stopping
any device on the same network from sending a function
code 5 and forcing a coil state or sending function code
6 and overwriting a register value. In a substation that
means breakers and relays. In a water treatment facility
that means pump states and valve positions. The protocol
was built for closed isolated networks and a lot of those
networks are not closed or isolated anymore.

The 2015 Ukraine attack is the clearest real example of
what this looks like. Attackers used ICS protocol
manipulation to open breakers at 30 substations at the
same time. 230,000 people lost power for six hours. The
behavioral signatures from that kind of attack are what
this project is built to catch before they get that far.

---

## Recommendations

1. Whitelist Modbus function codes at the network boundary.
   If a function code does not appear during normal
   operations it should never reach a PLC or RTU.

2. Deploy behavioral monitoring on OT segments. Signature
   based detection misses novel attacks. A baseline model
   catches deviations regardless of whether the specific
   pattern has been seen before.

3. Segment OT from IT networks and enforce strict access
   controls at every crossing point.

4. Compensate for the lack of Modbus authentication at the
   network layer through access control lists and monitoring.

5. Use NERC CIP CIP-007 as a baseline for system security
   management controls in power sector environments.

---

## Limitations

The contamination rate was a manual estimate. In a real
deployment you would tune that against labeled ground truth
and measure actual precision and recall numbers. This is
also offline only, running against live traffic would need
a network tap and a streaming pipeline.

The MITRE mapping ties technique IDs to function codes
which is a reasonable starting point but not fully precise.
Inspecting actual data payloads would make the technique
classification more accurate.
---

## Results Summary

| Metric | Value |
|---|---|
| Total packets analyzed | 8,215,496 |
| Anomalies detected | 408,382 |
| Detection rate | 4.97% |
| T0855 Unauthorized Command Message | 181,489 |
| T0836 Modify Parameter | 26,720 |
| T0843 Program Download | 10,297 |
| T0845 Program Upload | 85 |
| T0856 Spoof Reporting Message | 74 |
