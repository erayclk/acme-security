## 📋 Submission Information

**Name:Eray ÇELİK**  
**Email: eray0505@yandex.com** 
**LinkedIn:https://www.linkedin.com/in/erayclk]**  _(optional)_  
**Submission Date:2025-11-10** 

---

## ✅ Deliverables Checklist

Please confirm you've included all required items:

- [x] **Report** (PDF, max 5 pages)
  - [x] Section 1: Incident Analysis
  - [x] Section 2: Architecture Review
  - [x] Section 3: Response & Remediation
  
- [x] **Video Presentation** (10-15 minutes)
  - [x] Link provided in `video_link.md`
  - [x] Video is accessible (tested in incognito)
  - [x] Duration is within guidelines

- [x] **File Structure**
```
  submissions/firstname-lastname/
  ├── report.pdf
  ├── video_link.md
  └── notes.md (optional)
```

---

## 📊 Self-Assessment

**Time spent on this lab:** Approximately _11__ hours

**Tools used:**
- Log analysis: 5
- Diagrams: 4
- Video recording: 2

**Confidence level:**
- [x] Very confident in my analysis
- [ ] Confident but some uncertainties
- [ ] Attempted my best with available knowledge

---

## 🎯 Brief Summary (2-3 sentences)

_Briefly describe your approach and key findings:_

This report analyzes the multi-vector cyberattack against Acme Financial Services on October 15, 2024. Our approach involved reconstructing the incident timeline, identifying attack vectors (IDOR, SQLi, Phishing), conducting a Root Cause Analysis (RCA), and classifying the attack using industry frameworks (MITRE, OWASP).

The key finding is the attacker's 'procedural deception'  tactic. The attacker, aware of an upcoming penetration test , used an IP from the 'trusted' whitelist (203.0.113.0/24) to launch the attack five days before the test was scheduled. This was designed to make security alerts appear as 'normal test noise'. Under this cover, the attacker bypassed the WAF (which was in 'detect-only' mode) using an obfuscated SQL Injection payload to leak data , and exploited a critical IDOR (Broken Access Control) vulnerability in the mobile API to gain unauthorized access to 15 customer accounts.

---

## 🔍 Key Findings Highlight

**Main attack vectors identified:**
1. Stolen JWT Token & IDOR
2. Phishing
3. SQL Injection

**Most critical vulnerability:**
SQL injection

**Top recommendation:**
Removing the static 'trusted IP' (whitelist) lists that are used for planned tests.

Replacing them with "Just-in-Time" (JIT) access procedures.

Supporting this with immediate SIEM integration to detect and automatically block abnormal behavior (like accessing 5 different accounts in 1 minute), even if it comes from a 'trusted' IP

---

## 💭 Challenges & Learnings

**What was most challenging?**
The attacker's "procedural deception," (using a whitelisted IP ) made it difficult to distinguish the attack from "normal test noise"

**What did you learn?**
I learned that static procedural controls (like a whitelist ) combined with technical misconfigurations (like a "detect-only" WAF ) create a critical vulnerability.

**What would you do differently?**
I would immediately remove static whitelists and use SIEM correlation to detect and block abnormal behavior, even from "trusted" IPs

---

## 📝 Additional Notes _(optional)_

Any context, assumptions, or additional information you'd like evaluators to know:

[Write here]

---

## ⚖️ Declaration

I declare that:
- [x] This work is entirely my own
- [ ] I have not copied from other submissions or answer keys
- [ ] I have not modified the provided log files
- [ ] All sources and tools are properly attributed
- [ ] I understand plagiarism results in disqualification

**Signature:Eray ÇELİK** 
**Date:2025-10-11** 

---

## 🚀 Ready for Review

By submitting this PR, I confirm that my work is complete and ready for evaluation.

---

_Thank you for your submission! Our team will review it within 1 week._
