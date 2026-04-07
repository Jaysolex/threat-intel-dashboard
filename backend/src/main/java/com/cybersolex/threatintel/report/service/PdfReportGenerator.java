package com.cybersolex.threatintel.report.service;

import com.cybersolex.threatintel.report.domain.MitreAttackTechnique;
import com.cybersolex.threatintel.report.domain.ThreatReport;
import org.apache.pdfbox.pdmodel.*;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

@Component
public class PdfReportGenerator {

    public byte[] generate(ThreatReport report) throws IOException {

        try (PDDocument document = new PDDocument();
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            PDPage page = new PDPage();
            document.addPage(page);

            PDPageContentStream content = new PDPageContentStream(document, page);

            float y = 750;

            // TITLE
            content.beginText();
            content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 16);
            content.newLineAtOffset(50, y);
            content.showText("THREAT INTELLIGENCE REPORT");
            content.endText();

            y -= 30;

            // BASIC INFO
            content.beginText();
            content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 10);
            content.newLineAtOffset(50, y);
            content.showText("IP: " + report.getIpAddress());
            content.endText();

            y -= 15;

            content.beginText();
            content.newLineAtOffset(50, y);
            content.showText("Risk Score: " + report.getRiskScore() + " (" + report.getSeverity() + ")");
            content.endText();

            y -= 25;

            // EXEC SUMMARY
            content.beginText();
            content.newLineAtOffset(50, y);
            content.showText("Executive Summary:");
            content.endText();

            y -= 15;

            content.beginText();
            content.newLineAtOffset(50, y);
            content.showText(report.getExecutiveSummary());
            content.endText();

            y -= 25;

            // MITRE
            content.beginText();
            content.newLineAtOffset(50, y);
            content.showText("MITRE ATT&CK:");
            content.endText();

            y -= 15;

            for (MitreAttackTechnique t : report.getMitreAttackTechniques()) {
                content.beginText();
                content.newLineAtOffset(60, y);
                content.showText(t.getTechniqueId() + " - " + t.getName());
                content.endText();
                y -= 12;
            }

            y -= 15;

            // BUSINESS IMPACT
            content.beginText();
            content.newLineAtOffset(50, y);
            content.showText("Business Impact:");
            content.endText();

            y -= 15;

            content.beginText();
            content.newLineAtOffset(50, y);
            content.showText(report.getBusinessImpact());
            content.endText();

            y -= 25;

            // REMEDIATION
            content.beginText();
            content.newLineAtOffset(50, y);
            content.showText("Remediation:");
            content.endText();

            y -= 15;

            for (String step : report.getRemediationSteps()) {
                content.beginText();
                content.newLineAtOffset(60, y);
                content.showText("- " + step);
                content.endText();
                y -= 12;
            }

            content.close();

            document.save(out);
            return out.toByteArray();
        }
    }
}
