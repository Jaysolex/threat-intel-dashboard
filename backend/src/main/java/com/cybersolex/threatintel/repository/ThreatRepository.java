package com.cybersolex.threatintel.repository;

import com.cybersolex.threatintel.model.ThreatAnalysis;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ThreatRepository extends JpaRepository<ThreatAnalysis, Long> {
}
