package com.cybersolex.threatintel.model;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Entity
@Data
public class ThreatAnalysis {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String ip;

    private int riskScore;

    @Column(length = 2000)
    private String summary;

    private LocalDateTime createdAt;
}
