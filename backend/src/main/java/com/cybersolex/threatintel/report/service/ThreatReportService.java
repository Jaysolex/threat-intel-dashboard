package com.cybersolex.threatintel.report.service;

import com.cybersolex.threatintel.report.domain.MitreAttackTechnique;
import com.cybersolex.threatintel.report.domain.ThreatReport;
import com.cybersolex.threatintel.report.domain.ThreatReport.Severity;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class ThreatReportService {

public ThreatReport buildReport(Long id) {

// 🔥 TEMP: static data (we connect real DB later)
String ip = "185.220.101.1";
int riskScore = 178;
int abuseScore = 100;
int detections = 14;
int exposedServices = 4;

Severity severity = classify(riskScore);

List<MitreAttackTechnique> mitre = mapMitre(severity);

return ThreatReport.builder()
.id(id)
.ipAddress(ip)
.riskScore(riskScore)
.severity(severity)
.abuseConfidenceScore(abuseScore)
.maliciousDetections(detections)
.exposedServices(exposedServices)
.mitreAttackTechniques(mitre)
.executiveSummary(buildSummary(ip, severity))
.businessImpact(buildImpact(severity))
.remediationSteps(buildRemediation(severity))
.analystNotes("Auto-generated SOC report")
.build();
}

private Severity classify(int score) {
if (score >= 150) return Severity.CRITICAL;
if (score >= 80) return Severity.HIGH;
if (score >= 40) return Severity.MEDIUM;
return Severity.LOW;
}

private List<MitreAttackTechnique> mapMitre(Severity s) {
List<MitreAttackTechnique> list = new ArrayList<>();

if (s == Severity.CRITICAL || s == Severity.HIGH) {
list.add(new MitreAttackTechnique(
"T1595",
"Active Scanning",
"Reconnaissance",
"Attacker scanning for vulnerabilities"
));
}

if (s == Severity.MEDIUM) {
list.add(new MitreAttackTechnique(
"T1046",
"Service Discovery",
"Discovery",
"Checking open ports/services"
));
}

return list;
}

private String buildSummary(String ip, Severity s) {
return "IP " + ip + " is classified as " + s + " risk and may be involved in malicious activity.";
}

private String buildImpact(Severity s) {
return switch (s) {
case CRITICAL -> "High chance of compromise and lateral movement.";
case HIGH -> "Potential exploitation risk.";
case MEDIUM -> "Recon activity detected.";
case LOW -> "Minimal risk.";
};
}

private List<String> buildRemediation(Severity s) {
List<String> steps = new ArrayList<>();

steps.add("Block IP at firewall");
steps.add("Monitor logs");
steps.add("Enable IDS alerts");

if (s == Severity.CRITICAL || s == Severity.HIGH) {
steps.add("Start incident response");
}

return steps;
}
}
