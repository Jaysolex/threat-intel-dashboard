package com.cybersolex.threatintel.report.controller;

import com.cybersolex.threatintel.report.domain.ThreatReport;
import com.cybersolex.threatintel.report.service.PdfReportGenerator;
import com.cybersolex.threatintel.report.service.ThreatReportService;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.time.format.DateTimeFormatter;

@RestController
@RequestMapping("/api/report")
public class ReportController {

    private static final DateTimeFormatter FILE_DATE_FMT =
            DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    private final ThreatReportService reportService;
    private final PdfReportGenerator pdfGenerator;

    public ReportController(ThreatReportService reportService,
                            PdfReportGenerator pdfGenerator) {
        this.reportService = reportService;
        this.pdfGenerator = pdfGenerator;
    }

    @GetMapping("/{id}")
    public ResponseEntity<byte[]> generateReport(@PathVariable Long id)
            throws IOException {

        ThreatReport report = reportService.buildReport(id);
        byte[] pdf = pdfGenerator.generate(report);

        String filename = String.format("ThreatReport_%s_%s.pdf",
                report.getIpAddress().replace(".", "-"),
                report.getGeneratedAt().format(FILE_DATE_FMT));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentDisposition(
                ContentDisposition.attachment().filename(filename).build());
        headers.setContentType(MediaType.APPLICATION_PDF);

        return ResponseEntity.ok()
                .headers(headers)
                .body(pdf);
    }
}
