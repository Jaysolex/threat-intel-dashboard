package com.cybersolex.threatintel.report.domain;

public class MitreAttackTechnique {

    private String techniqueId;
    private String name;
    private String tactic;
    private String description;

    public MitreAttackTechnique(String id, String name, String tactic, String desc) {
        this.techniqueId = id;
        this.name = name;
        this.tactic = tactic;
        this.description = desc;
    }

    public String getTechniqueId() { return techniqueId; }
    public String getName() { return name; }
    public String getTactic() { return tactic; }
    public String getDescription() { return description; }
}
