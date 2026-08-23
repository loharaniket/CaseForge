# ThreatTrace AI — Sample Test Datasets & Sources

This directory contains sample `.eml` files for testing email ingestion, forensics, SPF/DKIM verification, and threat intelligence.

---

## 1. Local Pre-baked Samples in Repository

| File | Scenario | Key Forensic Indicators |
| :--- | :--- | :--- |
| [`phishing_urgent_invoice.eml`](file:///d:/git-repos/ThreatTrace-AI/samples/phishing_urgent_invoice.eml) | Overdue invoice phishing | SPF/DKIM/DMARC failure, wire transfer urgency, external URL |
| [`spam_lottery_prize.eml`](file:///d:/git-repos/ThreatTrace-AI/samples/spam_lottery_prize.eml) | International sweepstakes spam | SPF softfail, missing DKIM, credential harvest link |
| [`benign_team_meeting.eml`](file:///d:/git-repos/ThreatTrace-AI/samples/benign_team_meeting.eml) | Legitimate internal communication | SPF/DKIM/DMARC pass, legitimate enterprise headers |

---

## 2. Public Cybersecurity Datasets for Spam & Phishing .EML Files

You can download large public corpora for benchmark testing:

1. **Apache SpamAssassin Public Corpus**:
   - **URL**: https://spamassassin.apache.org/old/publiccorpus/
   - **Description**: Thousands of real-world spam and easy/hard ham emails formatted as raw RFC822 `.eml` files.
   - **Tar archives**: `20030228_spam.tar.bz2`, `20050311_spam_2.tar.bz2`, `20030228_easy_ham.tar.bz2`.

2. **Jose Nazario Phishing Corpus**:
   - **URL**: https://monkey.org/~jose/phishing/
   - **Description**: Historic dataset of thousands of targeted phishing emails in standard mbox / eml format.

3. **Enron Spam Dataset**:
   - **URL**: https://www.aueb.gr/users/ion/data/enron-spam/
   - **Description**: Raw spam and ham emails from the Enron corpus organized into numbered `.eml` files.

4. **Kaggle Phishing Email Datasets**:
   - **URL**: https://www.kaggle.com/datasets/subhajournal/phishingemails
   - **Description**: Tabular and raw email text collections containing phishing, BEC, and legitimate emails.

---

## 3. How to Export .EML from Your Own Email Client

- **Gmail**: Open any message -> Click the **3 vertical dots** (More options) -> Click **Download message** (`.eml`).
- **Microsoft Outlook (Web & Desktop)**: Open message -> Click **...** -> Click **View** -> **Save message** or drag the message to your desktop.
- **Apple Mail / Thunderbird**: Select message -> **File** -> **Save As...** -> Select **Raw Mail (.eml)** format.
