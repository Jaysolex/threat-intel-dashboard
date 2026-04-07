package com.cybersolex.threatintel.controller;

import com.cybersolex.threatintel.model.ThreatAnalysis;
import com.cybersolex.threatintel.model.Alert;
import com.cybersolex.threatintel.repository.ThreatRepository;
import com.cybersolex.threatintel.repository.AlertRepository;
import com.cybersolex.threatintel.service.ThreatService;
import com.cybersolex.threatintel.service.AIService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Map;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api/threat")
@RequiredArgsConstructor
public class ThreatController {

    private final ThreatRepository repository;
    private final ThreatService threatService;
    private final AIService aiService;
    private final AlertRepository alertRepository;

    @GetMapping("/analyze")
    public ThreatAnalysis analyze(@RequestParam String ip) {

        // API calls
        Map<String, Object> data = threatService.checkIP(ip);
        Map<String, Object> vtData = threatService.checkVirusTotal(ip);
        Map<String, Object> shodanData = threatService.checkShodan(ip);

        // AbuseIPDB
        int abuseScore = 0;
        try {
            Map abuse = (Map) data.get("data");
            abuseScore = (int) abuse.getOrDefault("abuseConfidenceScore", 0);
        } catch (Exception ignored) {}

        // VirusTotal
        int maliciousVotes = 0;
        try {
            Map vtStats = (Map) ((Map)((Map)vtData.get("data")).get("attributes")).get("last_analysis_stats");
            maliciousVotes = (int) vtStats.getOrDefault("malicious", 0);
        } catch (Exception ignored) {}

        // Shodan
        int openPorts = 0;
        try {
            openPorts = ((java.util.List<Integer>) shodanData.get("ports")).size();
        } catch (Exception ignored) {}

        // Final score (central engine)
        int finalScore = threatService.calculateRiskScore(data, vtData, shodanData, ip);

        // Severity classification
        String severity;
        if (finalScore > 150) severity = "CRITICAL";
        else if (finalScore > 80) severity = "HIGH";
        else if (finalScore > 40) severity = "MEDIUM";
        else severity = "LOW";

        // AI Summary
        String summary = aiService.generateSummary(ip, finalScore, severity);

        // Save analysis
        ThreatAnalysis t = new ThreatAnalysis();
        t.setIp(ip);
        t.setRiskScore(finalScore);
        t.setSummary(summary);
        t.setCreatedAt(LocalDateTime.now());

        ThreatAnalysis saved = repository.save(t);

        // 🚨 ALERT ENGINE (UPDATED → STORES IN DB)
        if (finalScore > 80) {

            Alert alert = new Alert();
            alert.setIp(ip);
            alert.setRiskScore(finalScore);
            alert.setSeverity(severity);
            alert.setMessage("Suspicious IP detected");
            alert.setCreatedAt(LocalDateTime.now());

            alertRepository.save(alert);

            System.out.println("🚨 ALERT STORED -> " + ip + " | " + severity);
        }

        return saved;
    }

    @GetMapping("/history")
    public java.util.List<ThreatAnalysis> getAll() {
        return repository.findAll();
    }

    @GetMapping("/alerts")
    public java.util.List<Alert> getAlerts() {
        return alertRepository.findAll();
    }

    @GetMapping("/health")
    public String health() {
        return "ThreatIntel API is running";
    }
}
