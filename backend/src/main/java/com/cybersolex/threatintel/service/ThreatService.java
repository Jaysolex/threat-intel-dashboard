package com.cybersolex.threatintel.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.RestClientException;
import org.springframework.http.*;

import java.util.Map;
import java.util.List;
import java.util.HashMap;

@Service
public class ThreatService {

    @Value("${abuseipdb.api-key}")
    private String apiKey;

    @Value("${virustotal.api-key}")
    private String vtApiKey;

    @Value("${shodan.api-key}")
    private String shodanApiKey;

    private final RestTemplate restTemplate = new RestTemplate();

    private static final List<String> MALICIOUS_IPS = List.of(
            "185.220.101.1",
            "45.33.32.156",
            "89.248.165.74",
            "192.42.116.16",
            "104.244.72.115",
            "23.129.64.210",
            "167.94.138.33",
            "80.82.77.33"
    );

    public Map<String, Object> checkIP(String ip) {
        try {
            String url = "https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip;

            HttpHeaders headers = new HttpHeaders();
            headers.set("Key", apiKey);
            headers.set("Accept", "application/json");

            HttpEntity<String> entity = new HttpEntity<>(headers);

            ResponseEntity<Map> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    entity,
                    Map.class
            );

            Map<String, Object> data = response.getBody();

            if (data == null) {
                data = new HashMap<>();
            }

            if (MALICIOUS_IPS.contains(ip)) {
                data.put("source", "IOC_THREAT_FEED");
            }

            return data;

        } catch (Exception e) {
            Map<String, Object> fallback = new HashMap<>();

            if (MALICIOUS_IPS.contains(ip)) {
                fallback.put("threatLevel", "HIGH");
            } else {
                fallback.put("threatLevel", "LOW");
            }

            return fallback;
        }
    }

    public Map<String, Object> checkVirusTotal(String ip) {
        try {
            String url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip;

            HttpHeaders headers = new HttpHeaders();
            headers.set("x-apikey", vtApiKey);

            HttpEntity<String> entity = new HttpEntity<>(headers);

            ResponseEntity<Map> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    entity,
                    Map.class
            );

            return response.getBody();

        } catch (Exception e) {
            return new HashMap<>();
        }
    }

    public Map<String, Object> checkShodan(String ip) {
        try {
            String url = "https://api.shodan.io/shodan/host/" + ip + "?key=" + shodanApiKey;

            ResponseEntity<Map> response = restTemplate.getForEntity(url, Map.class);

            return response.getBody();

        } catch (RestClientException e) {
            Map<String, Object> fallback = new HashMap<>();
            fallback.put("ports", new java.util.ArrayList<>());
            return fallback;
        }
    }

    public int calculateRiskScore(
            Map<String, Object> abuse,
            Map<String, Object> vt,
            Map<String, Object> shodan,
            String ip
    ) {

        int score = 0;

        if (MALICIOUS_IPS.contains(ip)) {
            score += 80;
        }

        if (abuse != null && abuse.containsKey("data")) {
            try {
                Map data = (Map) abuse.get("data");
                int abuseScore = (int) data.getOrDefault("abuseConfidenceScore", 0);

                if (abuseScore > 80) score += 70;
                else if (abuseScore > 50) score += 50;
                else if (abuseScore > 20) score += 30;

            } catch (Exception ignored) {}
        }

        if (vt != null && vt.containsKey("data")) {
            try {
                Map data = (Map) vt.get("data");
                Map attr = (Map) data.get("attributes");
                Map stats = (Map) attr.get("last_analysis_stats");

                int malicious = (int) stats.getOrDefault("malicious", 0);

                if (malicious > 10) score += 60;
                else if (malicious > 5) score += 40;
                else if (malicious > 0) score += 20;

            } catch (Exception ignored) {}
        }

        if (shodan != null && shodan.containsKey("ports")) {
            try {
                int ports = ((java.util.List<?>) shodan.get("ports")).size();

                if (ports > 5) score += 40;
                else if (ports > 2) score += 20;

            } catch (Exception ignored) {}
        }

        return score;
    }
}
