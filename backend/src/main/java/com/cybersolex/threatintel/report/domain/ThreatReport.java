package com.cybersolex.threatintel.report.domain;

import java.time.LocalDateTime;
import java.util.List;

public class ThreatReport {

    public enum Severity { LOW, MEDIUM, HIGH, CRITICAL }

    private Long id;
    private String ipAddress;
    private int riskScore;
    private Severity severity;
    private int abuseConfidenceScore;
    private int maliciousDetections;
    private int exposedServices;
    private List<MitreAttackTechnique> mitreAttackTechniques;
    private String executiveSummary;
    private String businessImpact;
    private List<String> remediationSteps;
    private String analystNotes;
    private LocalDateTime generatedAt = LocalDateTime.now();

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private final ThreatReport r = new ThreatReport();

        public Builder id(Long id) { r.id = id; return this; }
        public Builder ipAddress(String ip) { r.ipAddress = ip; return this; }
        public Builder riskScore(int s) { r.riskScore = s; return this; }
        public Builder severity(Severity s) { r.severity = s; return this; }
        public Builder abuseConfidenceScore(int s) { r.abuseConfidenceScore = s; return this; }
        public Builder maliciousDetections(int d) { r.maliciousDetections = d; return this; }
        public Builder exposedServices(int e) { r.exposedServices = e; return this; }
        public Builder mitreAttackTechniques(List<MitreAttackTechnique> m) { r.mitreAttackTechniques = m; return this; }
        public Builder executiveSummary(String s) { r.executiveSummary = s; return this; }
        public Builder businessImpact(String s) { r.businessImpact = s; return this; }
        public Builder remediationSteps(List<String> s) { r.remediationSteps = s; return this; }
        public Builder analystNotes(String s) { r.analystNotes = s; return this; }

        public ThreatReport build() { return r; }
    }

    // GETTERS ONLY

    public Long getId() { return id; }
    public String getIpAddress() { return ipAddress; }
    public int getRiskScore() { return riskScore; }
    public Severity getSeverity() { return severity; }
    public int getAbuseConfidenceScore() { return abuseConfidenceScore; }
    public int getMaliciousDetections() { return maliciousDetections; }
    public int getExposedServices() { return exposedServices; }
    public List<MitreAttackTechnique> getMitreAttackTechniques() { return mitreAttackTechniques; }
    public String getExecutiveSummary() { return executiveSummary; }
    public String getBusinessImpact() { return businessImpact; }
    public List<String> getRemediationSteps() { return remediationSteps; }
    public String getAnalystNotes() { return analystNotes; }
    public LocalDateTime getGeneratedAt() { return generatedAt; }
}
