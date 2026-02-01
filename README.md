# Detection Engineer Coding Exercises

Practice exercises for Detection Engineer interviews at companies like Datadog, Crowdstrike, Splunk, etc.

## Setup

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
pip install pandas httpx pyyaml fastapi uvicorn
```

---

## Exercise 1: Parse and Analyze Auth Logs

**File:** `exercise1_auth_logs.json`

**Task:** Write a script that:
1. Reads the JSON lines file
2. Identifies IPs with more than 5 failed login attempts within a 10-minute window
3. Outputs suspicious IPs with: count, first_seen, last_seen, usernames_attempted

**Expected detections:**
- 192.168.1.10 (7 failures in early window)
- 198.51.100.100 (8 rapid failures)
- 45.33.32.156 (6 rapid failures)
- 185.220.101.1 (7 rapid failures)

**Skills tested:** JSON parsing, time windowing, aggregation

---

## Exercise 2: IP Reputation Enrichment

**File:** `exercise2_ip_list.txt`

**Task:** Write a script that:
1. Reads IPs from the file
2. Queries AbuseIPDB or VirusTotal API (or mock the response)
3. Handles rate limiting (add sleep between requests)
4. Outputs CSV: ip, is_malicious, confidence_score, country, abuse_reports

**Bonus:** Add caching to avoid re-querying known IPs

**Skills tested:** API integration, rate limiting, error handling

---

## Exercise 3: Detection Rule Matcher

**Files:** `exercise3_rules.json`, `exercise3_events.json`

**Task:** Write a rule engine that:
1. Loads rules from JSON
2. Processes each event against all rules
3. Supports operators: equals, in, contains, contains_any, startswith, regex
4. Outputs: matched events with rule name and severity

**Expected matches:**
- RULE-001: SSH brute force events
- RULE-002: nc, nmap, mimikatz, psexec executions
- RULE-003: PowerShell EncodedCommand
- RULE-004: Connection to 185.220.101.1
- RULE-005: /etc/passwd, .ssh/id_rsa, .aws/credentials access
- RULE-006: sudo commands

**Skills tested:** Rule evaluation, pattern matching, abstraction

---

## Exercise 4: CloudTrail Log Analyzer

**File:** `exercise4_cloudtrail.json`

**Task:** Write a script that detects:
1. Console logins without MFA
2. Access key creation
3. Policy attachments (especially AdministratorAccess)
4. User creation followed by key creation (persistence pattern)
5. Reconnaissance activity (multiple Describe/List calls)
6. AccessDenied errors > 3 from same user
7. Attempts to disable CloudTrail

**Expected findings:**
- bob: Login without MFA, created access key, attached admin policy, created backdoor user
- backdoor-user: Reconnaissance activity, AccessDenied errors, attempted to stop CloudTrail

**Skills tested:** AWS security knowledge, attack pattern detection

---

## Exercise 5: Alert Deduplication Service

**File:** `exercise5_alerts.json`

**Task:** Build a FastAPI service that:
1. POST /alerts - receives alert JSON
2. Deduplicates based on (source_ip, alert_type, destination) within 5-minute window
3. Returns: {"status": "new|duplicate", "alert_id": "...", "duplicate_count": N}
4. GET /alerts/{id} - returns alert with duplicate count

**Test by sending alerts from the file and verify deduplication works**

**Skills tested:** HTTP APIs, state management, time windows

---

## Exercise 6: Sigma Rule to Query Converter

**File:** `exercise6_sigma_rules.yaml`

**Task:** Write a parser that:
1. Reads Sigma YAML rules
2. Converts detection logic to a query string (simplified)
3. Handles: contains, endswith, and, or, not

**Example output for first rule:**
```
(CommandLine:*EncodedCommand* OR CommandLine:*-enc* OR CommandLine:*bypass* OR CommandLine:*hidden* OR CommandLine:*noprofile*)
```

**Skills tested:** YAML parsing, query building, detection logic

---

## Exercise 7: Threat Intel Feed Aggregator

**Files:** `exercise7_feed_ips.csv`, `exercise7_feed_domains.json`

**Task:** Write a script that:
1. Reads multiple feed formats (CSV, JSON)
2. Normalizes to common schema: {indicator, type, source, threat_type, confidence, last_seen}
3. Deduplicates across sources
4. Outputs unified JSON blocklist

**Skills tested:** Data normalization, multiple formats, deduplication

---

## Exercise 8: Automated Response Webhook

**No input file - build the service**

**Task:** Build a FastAPI service:
1. POST /webhook - receives alert JSON
2. Based on alert_type, simulates response action:
   - "malware_detected" → log "Isolating host {destination}"
   - "brute_force" → log "Blocking IP {source_ip}"
   - "data_exfil" → log "Disabling user on {destination}"
3. Logs all actions to a file with timestamp
4. Returns action summary

**Test with alerts from exercise5_alerts.json**

**Skills tested:** Webhooks, conditional logic, audit logging

---

## Exercise 9: Detection Coverage Mapper

**File:** `exercise9_mitre_coverage.json`

**Task:** Write a script that:
1. Loads detection rules and target MITRE techniques
2. Calculates coverage percentage
3. Lists uncovered techniques
4. Identifies techniques with multiple rules (redundancy)
5. Considers only enabled rules

**Expected output:**
- Coverage: X% (Y of Z techniques)
- Uncovered: T1059.003, T1059.004, T1021.001, T1021.004, T1048, T1055.003, T1087.001, T1087.002
- Note: T1003.006 (DCSync) rule is disabled

**Skills tested:** Data analysis, set operations, reporting

---

## Exercise 10: Real-time Log Stream Processor

**File:** `exercise10_stream_logs.json`

**Task:** Write a processor that:
1. Reads events line by line (simulating a stream)
2. Maintains state for time-windowed detections
3. Detects:
   - Brute force: >5 failed logins from same IP in 60 seconds
   - Suspicious process: nc, ncat, netcat, nmap execution
   - Sensitive file access: /etc/passwd, /etc/shadow, .ssh/, .aws/
   - Data exfiltration: curl POST to external IP
   - Tor connection: connection to known Tor exit (185.220.101.1)
4. Outputs alerts in real-time as detected

**Skills tested:** Stream processing, stateful detection, real-time alerting

---

## Solutions Approach

For each exercise, your solution should:
1. Handle errors gracefully (malformed input, missing fields)
2. Include basic logging
3. Be readable and maintainable
4. Include comments explaining detection logic

Good luck!
