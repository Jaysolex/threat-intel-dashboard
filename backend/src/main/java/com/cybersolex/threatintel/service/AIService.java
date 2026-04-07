package com.cybersolex.threatintel.service;

import org.springframework.stereotype.Service;

@Service
public class AIService {

    public String generateSummary(String ip, int finalScore, String severity) {

        String summary;

        if ("CRITICAL".equals(severity)) {
            summary = "IP " + ip + " is classified as CRITICAL risk. Multiple strong indicators of compromise detected. Immediate action required.";
        } else if ("HIGH".equals(severity)) {
            summary = "IP " + ip + " is classified as HIGH risk. Likely involved in malicious activity such as scanning or exploitation.";
        } else if ("MEDIUM".equals(severity)) {
            summary = "IP " + ip + " shows suspicious behavior. Further monitoring is recommended.";
        } else {
            summary = "IP " + ip + " appears to be LOW risk. No strong indicators of malicious activity.";
        }

        return summary;
    }
}
