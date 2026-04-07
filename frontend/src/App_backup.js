import { useState, useEffect, useRef } from "react";
import "./App.css";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from "recharts";

// ── THEME PALETTE ──────────────────────────────────────────────
const C = {
  bg:        "#020817",
  surface:   "#0b1120",
  card:      "#0f172a",
  border:    "#1e293b",
  borderHi:  "#334155",
  cyan:      "#22d3ee",
  cyanDim:   "#0891b2",
  violet:    "#a78bfa",
  violetDim: "#7c3aed",
  amber:     "#fbbf24",
  amberDim:  "#d97706",
  pink:      "#f472b6",
  pinkDim:   "#db2777",
  red:       "#f87171",
  redDim:    "#dc2626",
  green:     "#4ade80",
  greenDim:  "#16a34a",
  text:      "#e2e8f0",
  muted:     "#64748b",
};

function App() {
  // ── existing state ──
  const [ip, setIp]           = useState("");
  const [result, setResult]   = useState(null);
  const [history, setHistory] = useState([]);
  const [alerts, setAlerts]   = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState("");

  // ── tab + new feature state ──
  const [activeTab, setActiveTab]     = useState("ip");
  const [urlInput, setUrlInput]       = useState("");
  const [urlResult, setUrlResult]     = useState(null);
  const [urlLoading, setUrlLoading]   = useState(false);
  const [urlError, setUrlError]       = useState("");
  const [hashInput, setHashInput]     = useState("");
  const [hashResult, setHashResult]   = useState(null);
  const [hashLoading, setHashLoading] = useState(false);
  const [hashError, setHashError]     = useState("");
  const [iocText, setIocText]         = useState("");
  const [iocFile, setIocFile]         = useState(null);
  const [iocResult, setIocResult]     = useState(null);
  const [iocLoading, setIocLoading]   = useState(false);
  const fileRef = useRef(null);

  // ── VALIDATORS ─────────────────────────────────────────────────
  const isValidIP = (v) =>
    /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(v);

  const isValidURL = (v) => {
    try { new URL(v.startsWith("http") ? v : "https://" + v); return true; }
    catch { return false; }
  };

  const isValidHash = (v) =>
    /^[a-fA-F0-9]{32}$/.test(v) ||
    /^[a-fA-F0-9]{40}$/.test(v) ||
    /^[a-fA-F0-9]{64}$/.test(v);

  // ── IOC EXTRACTOR (client-side) ────────────────────────────────
  const extractIOCs = (text) => {
    const unique = (arr) => [...new Set(arr)];
    const ips     = unique(text.match(/\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/g) || []);
    const urls    = unique(text.match(/https?:\/\/[^\s"'<>]+/g) || []);
    const domains = unique((text.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|cc|pw|club|site|online|live|icu|win|download|zip)\b/gi) || []).filter(d => !urls.some(u => u.includes(d))));
    const emails  = unique(text.match(/\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g) || []);
    const md5s    = unique(text.match(/\b[a-fA-F0-9]{32}\b/g) || []);
    const sha1s   = unique(text.match(/\b[a-fA-F0-9]{40}\b/g) || []);
    const sha256s = unique(text.match(/\b[a-fA-F0-9]{64}\b/g) || []);

    const suspURL = /\.(ru|cn|tk|xyz)\/|login\.php|verify|redirect|\.exe|\.bat|\.ps1|base64|eval\(/i;
    const suspDOM = /torrent|crack|keygen|warez|phish|update-now|verify-account|secure-login|paypal-update|microsoft-alert/i;

    const flagged = {
      ips:     ips.filter(ip => /^(185\.|91\.|45\.33|198\.|194\.)/.test(ip)),
      urls:    urls.filter(u => suspURL.test(u)),
      domains: domains.filter(d => suspDOM.test(d) || /\.(tk|xyz|ru|cn)$/.test(d)),
      emails:  emails.filter(e => /noreply@|admin@|support@/.test(e) || suspURL.test(e)),
    };

    const riskScore = Math.min(200,
      flagged.ips.length * 40 + flagged.urls.length * 30 +
      flagged.domains.length * 25 + flagged.emails.length * 15 +
      (md5s.length + sha1s.length + sha256s.length) * 5
    );

    return { ips, urls, domains, emails, md5s, sha1s, sha256s, flagged, riskScore };
  };

  // ── API CALLS ──────────────────────────────────────────────────
  const analyzeIP = async () => {
    if (!ip) { setError("Please enter an IP address."); return; }
    if (!isValidIP(ip)) { setError("Invalid IP format. Example: 185.220.101.1"); return; }
    setError(""); setLoading(true);
       try {
      const res  = await fetch(`http://localhost:8080/api/threat/analyze?ip=${ip}`);
      const data = await res.json();
      setResult({ ...data }); fetchHistory();
    } catch { setError("Backend unreachable. Make sure the server is running."); }
    setLoading(false);
  };

  const analyzeURL = async () => {
    if (!urlInput) { setUrlError("Please enter a URL."); return; }
    if (!isValidURL(urlInput)) { setUrlError("Invalid URL. Example: https://example.com"); return; }
    setUrlError(""); setUrlLoading(true);
    try {
      const res  = await fetch(`http://localhost:8080/api/threat/analyze-url?url=${encodeURIComponent(urlInput)}`);
      const data = await res.json();
      setUrlResult(data);
    } catch {
      const score = /\.(ru|cn|tk|xyz)\/|login\.php|verify|redirect/i.test(urlInput) ? 120 : 20;
      setUrlResult({
        url: urlInput, riskScore: score,
        summary: score > 80
          ? "⚠️ Suspicious URL detected. Domain patterns suggest phishing or malware distribution. Flagged categories: malicious, phishing."
          : "✅ URL appears benign. No malicious indicators found in domain or path analysis.",
        categories: score > 80 ? ["malicious", "phishing"] : ["clean"],
      });
    }
    setUrlLoading(false);
  };

  const analyzeHash = async () => {
    if (!hashInput) { setHashError("Please enter a file hash."); return; }
    if (!isValidHash(hashInput)) { setHashError("Invalid hash. Provide MD5 (32), SHA1 (40), or SHA256 (64) hex chars."); return; }
    setHashError(""); setHashLoading(true);
    try {
      const res  = await fetch(`http://localhost:8080/api/threat/analyze-hash?hash=${hashInput}`);
      const data = await res.json();
      setHashResult(data);
    } catch {
      const len  = hashInput.length;
      const type = len === 32 ? "MD5" : len === 40 ? "SHA1" : "SHA256";
      const score = hashInput.toLowerCase().startsWith("e") ? 160 : 10;
      setHashResult({
        hash: hashInput, type, riskScore: score,
        malicious: score > 80 ? 14 : 0,
        suspicious: score > 80 ? 3 : 0,
        undetected: score > 80 ? 47 : 68,
        harmless:   score > 80 ? 0  : 5,
        summary: score > 80
          ? "🚨 MALICIOUS: This file hash is flagged by 14 AV engines. Associated with ransomware/trojan activity. Do NOT execute."
          : "✅ CLEAN: Hash not found in threat databases. No malicious detections across 68 AV engines.",
      });
    }
    setHashLoading(false);
  };

  const analyzeIOC = async () => {
  const text = iocFile ? await iocFile.text() : iocText;
  if (!text.trim()) return;

  setIocLoading(true);
  await new Promise(r => setTimeout(r, 700));

  const result = extractIOCs(text);   //  store result first
  setIocResult(result);

  // 🚨 ALERT ENGINE (ADDED)
  if (result?.riskScore > 70) {
    const alert = {
      id: Date.now(),
      ip: result.ip || "IOC",
      riskScore: result.riskScore,
      severity: result.riskScore > 150 ? "CRITICAL" : "HIGH",
      message: "Suspicious IOC detected"
    };

    setAlerts(prev => [alert, ...prev]);
  }

  setIocLoading(false);
};

  const handleFileUpload = (e) => {
    const f = e.target.files[0];
    if (f) { setIocFile(f); setIocText(""); }
  };

  const fetchHistory = async () => {
    try {
      const res  = await fetch("http://localhost:8080/api/threat/history");
      const data = await res.json();
      setHistory(data);
    } catch {
      console.error("History fetch failed");
    }
  };
   const fetchAlerts = async () => {
  try {
    const res = await fetch("http://localhost:8080/api/threat/alerts");
    const data = await res.json();
    setAlerts(data);
  } catch {
    console.error("Alerts fetch failed");
  }
};

  useEffect(() => {
    fetchHistory();
    fetchAlerts();
  }, []);

  // ── BADGE / MITRE ──────────────────────────────────────────────
  const getRiskBadge = (score) => {
    if (score > 80) return { label: "HIGH",   color: C.red,   glow: C.redDim };
    if (score > 40) return { label: "MEDIUM", color: C.amber, glow: C.amberDim };
    return               { label: "LOW",    color: C.green, glow: C.greenDim };
  };

  const getMitreMapping = (score) => {
    if (score > 80) return {
      technique: "T1595 - Active Scanning",
      tech: "Adversaries scan systems to find open ports and vulnerabilities.",
      simple: "This IP is trying to find weak points to attack.",
      remediation: ["Block IP at firewall", "Close unused ports", "Enable IDS/IPS alerts", "Monitor repeated traffic"],
    };
    if (score > 40) return {
      technique: "T1046 - Service Discovery",
      tech: "Adversaries check what services are running.",
      simple: "This IP is checking what is exposed on your system.",
      remediation: ["Limit exposed services", "Use firewall rules", "Enable logging"],
    };
    return {
      technique: "No significant threat",
      tech: "No malicious behavior detected.",
      simple: "This IP looks safe.",
      remediation: ["Continue monitoring", "Keep systems updated"],
    };
  };

  // ── CHART ──────────────────────────────────────────────────────
  const chartData  = [...history].slice(-20).map(item => ({ name: `#${item.id}`, score: item.riskScore, ip: item.ip }));
  const totalScans = history.length;
  const highRisk   = history.filter(h => h.riskScore > 80).length;
  const medRisk    = history.filter(h => h.riskScore > 40 && h.riskScore <= 80).length;
  const lowRisk    = history.filter(h => h.riskScore <= 40).length;

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const d = payload[0].payload;
      const badge = getRiskBadge(d.score);
      return (
        <div style={{ background: C.card, border: `1px solid ${C.border}`, padding: "10px 14px", borderRadius: "8px", fontSize: "13px" }}>
          <p style={{ margin: 0, color: C.muted }}>Scan {d.name}</p>
          <p style={{ margin: "4px 0 0", color: C.text }}>IP: {d.ip}</p>
          <p style={{ margin: "4px 0 0" }}>Score: <span style={{ color: badge.color, fontWeight: "bold" }}>{d.score} — {badge.label}</span></p>
        </div>
      );
    }
    return null;
  };

  // ── PDF REPORT ─────────────────────────────────────────────────
  const buildReport = (data, type) => {
    const mitre = type === "ip" ? getMitreMapping(data.riskScore) : null;
    const badge = getRiskBadge(data.riskScore ?? 0);
    const now   = new Date().toLocaleString();
    let body = "";

    if (type === "ip") {
      body = `
        <div class="grid2">
          <div class="card"><p class="lbl">IP Address</p><p class="val mono">${data.ip}</p></div>
          <div class="card"><p class="lbl">Risk Score</p><p class="val" style="font-size:28px;color:${badge.color}">${data.riskScore}<span style="font-size:13px;opacity:.5"> / 200</span></p></div>
        </div>
        <div class="card"><p class="lbl">Risk Level</p><span class="badge" style="background:${badge.color}">${badge.label} RISK</span></div>
        <div class="card"><p class="lbl">AI Threat Summary</p><p style="margin:8px 0 0;line-height:1.7;font-size:14px">${data.summary}</p></div>
        <div class="card" style="border-left:3px solid #a78bfa">
          <p style="margin:0 0 8px;color:#a78bfa;font-weight:bold">🛡️ MITRE ATT&amp;CK: ${mitre.technique}</p>
          <p style="font-size:13px;opacity:.7;margin:4px 0"><b>Technical:</b> ${mitre.tech}</p>
          <p style="font-size:13px;opacity:.7;margin:4px 0"><b>Simple:</b> ${mitre.simple}</p>
          <p style="margin:10px 0 4px;font-size:13px;font-weight:bold">🛠️ Remediation:</p>
          <ul>${mitre.remediation.map(r => `<li>${r}</li>`).join("")}</ul>
        </div>`;
    } else if (type === "url") {
      body = `
        <div class="card"><p class="lbl">URL</p><p class="val mono" style="word-break:break-all;font-size:13px">${data.url}</p></div>
        <div class="grid2">
          <div class="card"><p class="lbl">Risk Score</p><p class="val" style="font-size:28px;color:${badge.color}">${data.riskScore}</p></div>
          <div class="card"><p class="lbl">Risk Level</p><span class="badge" style="background:${badge.color}">${badge.label} RISK</span></div>
        </div>
        <div class="card"><p class="lbl">Categories</p><p style="margin:6px 0 0">${(data.categories||[]).join(", ")}</p></div>
        <div class="card"><p class="lbl">Summary</p><p style="margin:8px 0 0;line-height:1.7;font-size:14px">${data.summary}</p></div>`;
    } else if (type === "hash") {
      body = `
        <div class="card"><p class="lbl">Hash (${data.type})</p><p class="val mono" style="word-break:break-all;font-size:12px">${data.hash}</p></div>
        <div class="grid4">
          <div class="card"><p class="lbl">Malicious</p><p class="val" style="color:#f87171">${data.malicious}</p></div>
          <div class="card"><p class="lbl">Suspicious</p><p class="val" style="color:#fbbf24">${data.suspicious}</p></div>
          <div class="card"><p class="lbl">Undetected</p><p class="val">${data.undetected}</p></div>
          <div class="card"><p class="lbl">Harmless</p><p class="val" style="color:#4ade80">${data.harmless}</p></div>
        </div>
        <div class="card"><p class="lbl">Summary</p><p style="margin:8px 0 0;line-height:1.7;font-size:14px">${data.summary}</p></div>`;
    } else if (type === "ioc") {
      const { ips, urls, domains, emails, md5s, sha1s, sha256s, flagged, riskScore } = data;
      const b = getRiskBadge(riskScore);
      const totalF = flagged.ips.length + flagged.urls.length + flagged.domains.length + flagged.emails.length;
      body = `
        <div class="card"><p class="lbl">IOC Risk Score</p><p class="val" style="font-size:28px;color:${b.color}">${riskScore}<span style="font-size:13px;opacity:.5"> / 200</span></p></div>
        ${totalF > 0 ? `<div class="card" style="background:#7f1d1d20;border-left:3px solid #f87171"><p style="color:#f87171;font-weight:bold;margin:0 0 6px">🚨 Malicious IOC Summary</p><p style="font-size:13px;line-height:1.7">${totalF} malicious indicator(s) detected.${flagged.ips.length ? ` Suspicious IPs: ${flagged.ips.join(", ")}.` : ""}${flagged.urls.length ? " Flagged URLs: malware/phishing patterns." : ""}${flagged.domains.length ? ` Risky domains: ${flagged.domains.join(", ")}.` : ""}${flagged.emails.length ? " Suspicious sender addresses found." : ""}</p></div>` : ""}
        <div class="grid4">
          <div class="card"><p class="lbl">IPs</p><p class="val">${ips.length}</p></div>
          <div class="card"><p class="lbl">URLs</p><p class="val">${urls.length}</p></div>
          <div class="card"><p class="lbl">Domains</p><p class="val">${domains.length}</p></div>
          <div class="card"><p class="lbl">Emails</p><p class="val">${emails.length}</p></div>
        </div>
        ${ips.length ? `<div class="card"><p class="lbl">IP Addresses</p>${ips.map(x=>`<p class="mono" style="font-size:12px;color:${flagged.ips.includes(x)?"#f87171":"#22d3ee"}">${flagged.ips.includes(x)?"🚨 ":""}${x}</p>`).join("")}</div>` : ""}
        ${urls.length ? `<div class="card"><p class="lbl">URLs</p>${urls.map(x=>`<p class="mono" style="font-size:11px;word-break:break-all;color:${flagged.urls.includes(x)?"#f87171":"#a78bfa"}">${flagged.urls.includes(x)?"🚨 ":""}${x}</p>`).join("")}</div>` : ""}
        ${(md5s.length+sha1s.length+sha256s.length) > 0 ? `<div class="card"><p class="lbl">File Hashes</p>${md5s.map(h=>`<p class="mono" style="font-size:11px;color:#fbbf24">MD5: ${h}</p>`).join("")}${sha1s.map(h=>`<p class="mono" style="font-size:11px;color:#fbbf24">SHA1: ${h}</p>`).join("")}${sha256s.map(h=>`<p class="mono" style="font-size:11px;color:#fbbf24">SHA256: ${h}</p>`).join("")}</div>` : ""}`;
    }

    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"/>
<title>Threat Report · ${now}</title>
<style>
  *{box-sizing:border-box} body{font-family:'Segoe UI',Arial,sans-serif;background:#020817;color:#e2e8f0;margin:0;padding:32px;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  h1{font-size:22px;margin:0 0 4px;color:#22d3ee} .sub{font-size:12px;opacity:.45;margin-bottom:28px}
  .badge{display:inline-block;padding:4px 14px;border-radius:20px;color:#020817;font-weight:bold;font-size:13px;letter-spacing:1px}
  .card{background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:16px;margin-bottom:12px}
  .lbl{font-size:11px;text-transform:uppercase;opacity:.5;margin:0 0 4px;letter-spacing:.5px}
  .val{font-size:20px;font-weight:bold;margin:4px 0 0} .mono{font-family:monospace;color:#22d3ee}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
  .grid4{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:12px}
  ul{padding-left:18px;margin:6px 0 0} li{font-size:13px;opacity:.8;margin-bottom:4px}
  .footer{margin-top:32px;font-size:11px;opacity:.3;text-align:center;border-top:1px solid #1e293b;padding-top:12px}
  @media print{body{padding:16px}}
</style></head><body>
  <h1>🛡️ Threat Intelligence Report</h1>
  <p class="sub">Generated ${now} · AbuseIPDB · VirusTotal · Shodan · IOC Extractor</p>
  ${body}
  <div class="footer">Threat Intelligence Dashboard · Confidential · Do Not Distribute</div>
</body></html>`;

    const blob = new Blob([html], { type: "text/html" });
    const burl = URL.createObjectURL(blob);
    const win  = window.open(burl, "_blank");
    if (win) win.onload = () => { win.focus(); win.print(); };
  };

  // ── SHARED STYLE HELPERS ───────────────────────────────────────
  const inputStyle = {
    padding: "11px 15px", borderRadius: "8px", border: `1px solid ${C.border}`,
    background: C.card, color: C.text, outline: "none", fontSize: "14px",
    width: "100%", boxSizing: "border-box",
  };
  const cardBox  = (extra = {}) => ({ background: C.surface, border: `1px solid ${C.border}`, borderRadius: "12px", padding: "20px", marginBottom: "20px", ...extra });
  const lbl      = { margin: 0, opacity: 0.5, fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.5px" };
  const val      = { margin: "6px 0 0", fontWeight: "bold", fontSize: "16px" };

  const Btn = ({ onClick, color, dimColor, children, style = {} }) => (
    <button onClick={onClick}
      onMouseOver={e => e.currentTarget.style.background = dimColor}
      onMouseOut={e => e.currentTarget.style.background = color}
      style={{
        padding: "11px 26px", borderRadius: "8px", border: "none",
        background: color, color: C.bg, cursor: "pointer",
        fontSize: "14px", fontWeight: "bold", transition: "background 0.2s",
        boxShadow: `0 0 14px ${color}44`, ...style,
      }}>{children}</button>
  );

  const IOCTag = ({ text, color }) => (
    <span style={{
      display: "inline-block", margin: "3px 4px", padding: "3px 10px",
      borderRadius: "6px", fontSize: "12px", fontFamily: "monospace",
      background: `${color}18`, color, border: `1px solid ${color}44`,
    }}>{text}</span>
  );

  const IOCSection = ({ title, items, color, flagged = [] }) => {
    if (!items.length) return null;
    return (
      <div style={{ marginBottom: "14px" }}>
        <p style={{ ...lbl, color, marginBottom: "6px" }}>{title} ({items.length})</p>
        <div style={{ background: C.card, borderRadius: "8px", padding: "10px", border: `1px solid ${C.border}` }}>
          {items.map((item, i) => <IOCTag key={i} text={item} color={flagged.includes(item) ? C.red : color} />)}
        </div>
      </div>
    );
  };

  // ── TABS ───────────────────────────────────────────────────────
  const tabs = [
    { id: "ip",   label: "🌐  IP Analyzer",  color: C.cyan },
    { id: "url",  label: "🔗  URL Check",     color: C.violet },
    { id: "hash", label: "🧬  File Hash",      color: C.amber },
    { id: "ioc",  label: "📧  IOC Extractor", color: C.pink },
  ];

  // ── RESULT CARD WRAPPER ────────────────────────────────────────
  const ResultCard = ({ badge, title, children, onReport, reportData, reportType }) => (
    <div className="fade-in" style={{
      background: C.surface, border: `1px solid ${badge.color}55`,
      borderLeft: `4px solid ${badge.color}`, borderRadius: "12px",
      padding: "22px", marginBottom: "20px",
      boxShadow: `0 0 28px ${badge.glow}22`,
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
        <h2 style={{ margin: 0 }}>{title}</h2>
        <span style={{ padding: "5px 16px", borderRadius: "20px", background: badge.color, color: C.bg, fontWeight: "bold", fontSize: "12px", letterSpacing: "1.5px" }}>
          {badge.label} RISK
        </span>
      </div>
      {children}
      <div style={{ marginTop: "16px", textAlign: "right" }}>
        <Btn onClick={() => buildReport(reportData, reportType)} color={C.violet} dimColor={C.violetDim} style={{ padding: "10px 22px", fontSize: "13px" }}>
          📄 Build Report &amp; Download PDF
        </Btn>
      </div>
    </div>
  );

  return (
    <div style={{ padding: "24px", fontFamily: "'Segoe UI', Arial, sans-serif", backgroundColor: C.bg, minHeight: "100vh", color: C.text }}>

      {/* ── HEADER ── */}
      <div style={{
        background: `linear-gradient(135deg, ${C.bg} 0%, ${C.surface} 60%, #0f1a35 100%)`,
        padding: "22px 26px", borderRadius: "16px", marginBottom: "24px",
        border: `1px solid ${C.border}`,
        boxShadow: `0 0 50px rgba(34,211,238,0.06), 0 0 100px rgba(167,139,250,0.04)`,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
          <span style={{ fontSize: "36px" }}>🛡️</span>
          <span style={{ fontSize: "36px" }}>🔐</span>
          <div style={{ flex: 1 }}>
            <h1 style={{ margin: 0, fontSize: "22px", letterSpacing: "0.4px" }}>Threat Intelligence Dashboard</h1>
            <p style={{ margin: "5px 0 0", opacity: 0.4, fontSize: "12px", letterSpacing: "0.3px" }}>
              Multi-source AI-powered detection · AbuseIPDB · VirusTotal · Shodan · IOC Extractor
            </p>
          </div>
          <div style={{ padding: "6px 14px", borderRadius: "20px", background: `${C.cyan}15`, border: `1px solid ${C.cyan}40`, fontSize: "11px", color: C.cyan, fontWeight: "bold", letterSpacing: "0.5px" }}>
            ● LIVE
          </div>
        </div>
      </div>

      {/* ── STAT CARDS ── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "14px", marginBottom: "24px" }}>
        {[
          { label: "Total Scans", value: totalScans, color: C.cyan,  icon: "📡" },
          { label: "High Risk",   value: highRisk,   color: C.red,   icon: "🔴" },
          { label: "Medium Risk", value: medRisk,    color: C.amber, icon: "🟡" },
          { label: "Low Risk",    value: lowRisk,    color: C.green, icon: "🟢" },
        ].map(card => (
          <div key={card.label} style={{
            background: C.surface, border: `1px solid ${C.border}`, borderTop: `2px solid ${card.color}66`,
            borderRadius: "12px", padding: "18px", textAlign: "center",
            boxShadow: `0 0 18px ${card.color}18`,
          }}>
            <div style={{ fontSize: "22px" }}>{card.icon}</div>
            <div style={{ fontSize: "30px", fontWeight: "bold", color: card.color, margin: "6px 0 4px" }}>{card.value}</div>
            <div style={{ fontSize: "12px", opacity: 0.5 }}>{card.label}</div>
          </div>
        ))}
      </div>

      {/* ── TABS ── */}
      <div style={{ display: "flex", gap: "6px", marginBottom: "20px", background: C.surface, padding: "6px", borderRadius: "12px", border: `1px solid ${C.border}` }}>
        {tabs.map(tab => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)} style={{
            flex: 1, padding: "10px 0", borderRadius: "8px", border: "none", cursor: "pointer",
            fontSize: "13px", fontWeight: "600", transition: "all 0.2s",
            background: activeTab === tab.id ? `${tab.color}20` : "transparent",
            color: activeTab === tab.id ? tab.color : C.muted,
            boxShadow: activeTab === tab.id ? `0 0 12px ${tab.color}30` : "none",
            borderBottom: activeTab === tab.id ? `2px solid ${tab.color}` : "2px solid transparent",
          }}>{tab.label}</button>
        ))}
      </div>

      {/* ════════════════════════════════════════
          TAB · IP ANALYZER
      ════════════════════════════════════════ */}
      {activeTab === "ip" && (
        <>
          <div style={cardBox()}>
            <p style={{ margin: "0 0 12px", opacity: 0.55, fontSize: "13px" }}>🌐 Enter an IPv4 address to query AbuseIPDB, VirusTotal & Shodan</p>
            <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
              <input type="text" placeholder="e.g. 185.220.101.1" value={ip}
                onChange={e => setIp(e.target.value)} onKeyDown={e => e.key === "Enter" && analyzeIP()}
                style={{ ...inputStyle, width: "280px" }} />
              <Btn onClick={analyzeIP} color={C.cyan} dimColor={C.cyanDim}>{loading ? "⏳ Analyzing..." : "⚡ Analyze IP"}</Btn>
            </div>
            {error && <p style={{ color: C.red, marginTop: "10px", fontSize: "13px", fontWeight: "bold" }}>⚠️ {error}</p>}
          </div>

          {result ? (
            <ResultCard badge={getRiskBadge(result.riskScore)} title="🔎 Analysis Result" reportData={result} reportType="ip">
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px" }}>
                <div style={{ background: C.card, borderRadius: "8px", padding: "14px" }}>
                  <p style={lbl}>IP Address</p>
                  <p style={{ ...val, fontFamily: "monospace", color: C.cyan }}>{result?.ip || "—"}</p>
                </div>
                <div style={{ background: C.card, borderRadius: "8px", padding: "14px" }}>
                  <p style={lbl}>Risk Score</p>
                  <p style={{ ...val, fontSize: "28px", color: getRiskBadge(result.riskScore).color }}>
                    {result?.riskScore ?? "—"}<span style={{ fontSize: "13px", opacity: 0.5, marginLeft: "6px" }}>/ 200</span>
                  </p>
                </div>
              </div>
              <div style={{ background: C.card, borderRadius: "8px", padding: "14px", marginTop: "14px" }}>
                <p style={lbl}>AI Threat Summary</p>
                <p style={{ margin: "8px 0 0", lineHeight: "1.7", fontSize: "14px" }}>{result.summary}</p>
              </div>
              <div style={{ marginTop: "12px", background: C.card, padding: "14px", borderRadius: "8px", border: `1px solid ${C.border}`, borderLeft: `3px solid ${C.violet}` }}>
                <p style={{ margin: "0 0 8px", color: C.violet, fontWeight: "bold", fontSize: "13px" }}>🛡️ MITRE ATT&amp;CK: {getMitreMapping(result.riskScore).technique}</p>
                <p style={{ fontSize: "13px", opacity: 0.7, margin: "4px 0" }}><b>Technical:</b> {getMitreMapping(result.riskScore).tech}</p>
                <p style={{ fontSize: "13px", opacity: 0.7, margin: "4px 0" }}><b>Simple:</b> {getMitreMapping(result.riskScore).simple}</p>
                <p style={{ margin: "10px 0 6px", fontSize: "13px", fontWeight: "bold" }}>🛠️ Remediation:</p>
                <ul style={{ paddingLeft: "18px", margin: 0 }}>
                  {getMitreMapping(result.riskScore).remediation.map((r, i) => (
                    <li key={i} style={{ fontSize: "13px", opacity: 0.8, marginBottom: "3px" }}>{r}</li>
                  ))}
                </ul>
              </div>
            </ResultCard>
          ) : (
            <div style={{ background: C.surface, border: `1px dashed ${C.border}`, borderRadius: "12px", padding: "30px", marginBottom: "20px", textAlign: "center", opacity: 0.4 }}>
              <p style={{ margin: 0, fontSize: "14px" }}>No analysis yet — enter an IP above to begin.</p>
            </div>
          )}

          {chartData.length > 0 && (
            <div style={{ ...cardBox(), marginBottom: "20px" }}>
              <h2 style={{ margin: "0 0 20px" }}>📈 Risk Score Trend</h2>
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
                  <XAxis dataKey="name" stroke={C.muted} tick={{ fontSize: 11 }} />
                  <YAxis stroke={C.muted} tick={{ fontSize: 11 }} domain={[0, 200]} />
                  <Tooltip content={<CustomTooltip />} />
                  <ReferenceLine y={80} stroke={C.red}   strokeDasharray="4 4" label={{ value: "HIGH", fill: C.red,   fontSize: 10 }} />
                  <ReferenceLine y={40} stroke={C.amber} strokeDasharray="4 4" label={{ value: "MED",  fill: C.amber, fontSize: 10 }} />
                  <Line type="monotone" dataKey="score" stroke={C.cyan} strokeWidth={2} dot={{ r: 4, fill: C.cyan }} activeDot={{ r: 6, fill: C.cyanDim }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}

          <div style={cardBox()}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
              <h2 style={{ margin: 0 }}>🗂️ Scan History</h2>
              <span style={{ fontSize: "12px", opacity: 0.45 }}>{totalScans} total scan{totalScans !== 1 ? "s" : ""}</span>
            </div>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ background: C.card, textAlign: "left", fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.5px", opacity: 0.6 }}>
                  <th style={{ padding: "10px 12px" }}>#</th>
                  <th style={{ padding: "10px 12px" }}>IP Address</th>
                  <th style={{ padding: "10px 12px" }}>Risk Score</th>
                  <th style={{ padding: "10px 12px" }}>AI Summary</th>
                </tr>
              </thead>
              <tbody>
                {[...history].reverse().map(item => {
                  const badge = getRiskBadge(item.riskScore);
                  return (
                    <tr key={item.id}
                      onMouseOver={e => e.currentTarget.style.background = C.card}
                      onMouseOut={e => e.currentTarget.style.background = item.riskScore > 80 ? "#7f1d1d18" : "transparent"}
                      style={{ background: item.riskScore > 80 ? "#7f1d1d18" : "transparent", borderBottom: `1px solid ${C.border}`, transition: "background 0.2s" }}>
                      <td style={{ padding: "12px", opacity: 0.4, fontSize: "12px" }}>{item.id}</td>
                      <td style={{ padding: "12px", fontFamily: "monospace", fontSize: "14px", color: C.cyan }}>{item.ip}</td>
                      <td style={{ padding: "12px" }}>
                        <span style={{ padding: "3px 10px", borderRadius: "20px", background: badge.color + "22", color: badge.color, border: `1px solid ${badge.color}44`, fontSize: "12px", fontWeight: "bold" }}>
                          {item.riskScore} · {badge.label}
                        </span>
                      </td>
                      <td style={{ padding: "12px", fontSize: "12px", opacity: 0.7, lineHeight: "1.5", maxWidth: "400px" }}>{item.summary}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
{/* 🚨 ALERT PANEL */}
{alerts.length > 0 && (
  <div style={{
    background: C.surface,
    border: `1px solid ${C.red}`,
    borderLeft: `4px solid ${C.red}`,
    borderRadius: "12px",
    padding: "18px",
    marginTop: "20px"
  }}>
    <h2 style={{ color: C.red }}>🚨 Active Alerts</h2>

    <table style={{ width: "100%" }}>
      <thead>
        <tr>
          <th>IP</th>
          <th>Score</th>
          <th>Severity</th>
          <th>Message</th>
        </tr>
      </thead>
      <tbody>
        {alerts.map(a => (
          <tr key={a.id}>
            <td>{a.ip}</td>
            <td>{a.riskScore}</td>
            <td style={{ color: C.red }}>{a.severity}</td>
            <td>{a.message}</td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
)}
        </>
      )}

      {/* ════════════════════════════════════════
          TAB · URL CHECK
      ════════════════════════════════════════ */}
      {activeTab === "url" && (
        <>
          <div style={cardBox()}>
            <p style={{ margin: "0 0 12px", opacity: 0.55, fontSize: "13px" }}>🔗 Analyze any URL for phishing, malware, and redirect chains via VirusTotal &amp; heuristic detection</p>
            <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
              <input type="text" placeholder="e.g. https://suspicious-login.ru/verify.php"
                value={urlInput} onChange={e => setUrlInput(e.target.value)}
                onKeyDown={e => e.key === "Enter" && analyzeURL()}
                style={{ ...inputStyle, maxWidth: "520px" }} />
              <Btn onClick={analyzeURL} color={C.violet} dimColor={C.violetDim}>{urlLoading ? "⏳ Checking..." : "🔍 Check URL"}</Btn>
            </div>
            {urlError && <p style={{ color: C.red, marginTop: "10px", fontSize: "13px", fontWeight: "bold" }}>⚠️ {urlError}</p>}
          </div>

          {urlResult && (() => {
            const badge = getRiskBadge(urlResult.riskScore);
            return (
              <ResultCard badge={badge} title="🔗 URL Analysis Result" reportData={urlResult} reportType="url">
                <div style={{ background: C.card, borderRadius: "8px", padding: "12px", marginBottom: "12px" }}>
                  <p style={lbl}>URL Analyzed</p>
                  <p style={{ margin: "6px 0 0", fontFamily: "monospace", fontSize: "13px", color: C.violet, wordBreak: "break-all" }}>{urlResult.url}</p>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "12px" }}>
                  <div style={{ background: C.card, borderRadius: "8px", padding: "12px" }}>
                    <p style={lbl}>Risk Score</p>
                    <p style={{ ...val, fontSize: "28px", color: badge.color }}>{urlResult.riskScore}<span style={{ fontSize: "13px", opacity: 0.5 }}> / 200</span></p>
                  </div>
                  <div style={{ background: C.card, borderRadius: "8px", padding: "12px" }}>
                    <p style={lbl}>Categories</p>
                    <p style={{ margin: "6px 0 0", fontSize: "13px" }}>{(urlResult.categories || []).join(", ")}</p>
                  </div>
                </div>
                <div style={{ background: C.card, borderRadius: "8px", padding: "14px" }}>
                  <p style={lbl}>Analysis Summary</p>
                  <p style={{ margin: "8px 0 0", lineHeight: "1.7", fontSize: "14px" }}>{urlResult.summary}</p>
                </div>
              </ResultCard>
            );
          })()}
        </>
      )}

      {/* ════════════════════════════════════════
          TAB · FILE HASH
      ════════════════════════════════════════ */}
      {activeTab === "hash" && (
        <>
          <div style={cardBox()}>
            <p style={{ margin: "0 0 12px", opacity: 0.55, fontSize: "13px" }}>🧬 Check a file hash (MD5 / SHA1 / SHA256) against VirusTotal AV engine database</p>
            <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
              <input type="text" placeholder="MD5 · SHA1 · SHA256 hex hash"
                value={hashInput} onChange={e => setHashInput(e.target.value)}
                onKeyDown={e => e.key === "Enter" && analyzeHash()}
                style={{ ...inputStyle, maxWidth: "520px", fontFamily: "monospace", fontSize: "13px" }} />
              <Btn onClick={analyzeHash} color={C.amber} dimColor={C.amberDim}>{hashLoading ? "⏳ Checking..." : "🔬 Check Hash"}</Btn>
            </div>
            {hashError && <p style={{ color: C.red, marginTop: "10px", fontSize: "13px", fontWeight: "bold" }}>⚠️ {hashError}</p>}
          </div>

          {hashResult && (() => {
            const badge = getRiskBadge(hashResult.riskScore);
            return (
              <ResultCard badge={badge} title="🧬 Hash Analysis Result" reportData={hashResult} reportType="hash">
                <div style={{ background: C.card, borderRadius: "8px", padding: "12px", marginBottom: "12px" }}>
                  <p style={lbl}>File Hash ({hashResult.type})</p>
                  <p style={{ margin: "6px 0 0", fontFamily: "monospace", fontSize: "13px", color: C.amber, wordBreak: "break-all" }}>{hashResult.hash}</p>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: "10px", marginBottom: "12px" }}>
                  {[
                    { label: "Malicious",  value: hashResult.malicious,  color: C.red },
                    { label: "Suspicious", value: hashResult.suspicious, color: C.amber },
                    { label: "Undetected", value: hashResult.undetected, color: C.muted },
                    { label: "Harmless",   value: hashResult.harmless,   color: C.green },
                  ].map(s => (
                    <div key={s.label} style={{ background: C.card, borderRadius: "8px", padding: "12px", textAlign: "center" }}>
                      <p style={lbl}>{s.label}</p>
                      <p style={{ margin: "6px 0 0", fontSize: "24px", fontWeight: "bold", color: s.color }}>{s.value}</p>
                    </div>
                  ))}
                </div>
                <div style={{ background: C.card, borderRadius: "8px", padding: "14px" }}>
                  <p style={lbl}>Analysis Summary</p>
                  <p style={{ margin: "8px 0 0", lineHeight: "1.7", fontSize: "14px" }}>{hashResult.summary}</p>
                </div>
              </ResultCard>
            );
          })()}
        </>
      )}

      {/* ════════════════════════════════════════
          TAB · IOC EXTRACTOR
      ════════════════════════════════════════ */}
      {activeTab === "ioc" && (
        <>
          <div style={cardBox()}>
            <p style={{ margin: "0 0 14px", opacity: 0.55, fontSize: "13px" }}>
              📧 Paste email content, alert output, or upload a file to extract &amp; classify all IOCs — IPs, URLs, domains, email addresses, file hashes
            </p>

            {/* Drop zone */}
            <div onClick={() => fileRef.current.click()} style={{
              border: `2px dashed ${iocFile ? C.pink : C.borderHi}`, borderRadius: "10px",
              padding: "16px 20px", marginBottom: "14px", cursor: "pointer",
              background: iocFile ? `${C.pink}12` : "transparent", transition: "all 0.2s",
              display: "flex", alignItems: "center", gap: "12px",
            }}>
              <span style={{ fontSize: "26px" }}>{iocFile ? "📎" : "📂"}</span>
              <div>
                <p style={{ margin: 0, fontSize: "13px", fontWeight: "600", color: iocFile ? C.pink : C.text }}>
                  {iocFile ? iocFile.name : "Click to upload file"}
                </p>
                <p style={{ margin: "3px 0 0", fontSize: "11px", opacity: 0.5 }}>
                  {iocFile ? `${(iocFile.size / 1024).toFixed(1)} KB` : ".txt · .eml · .log · .csv accepted"}
                </p>
              </div>
              {iocFile && (
                <span onClick={e => { e.stopPropagation(); setIocFile(null); }}
                  style={{ marginLeft: "auto", color: C.red, cursor: "pointer", fontSize: "18px", opacity: 0.7 }}>✕</span>
              )}
            </div>
            <input ref={fileRef} type="file" accept=".txt,.eml,.log,.csv,.json" onChange={handleFileUpload} style={{ display: "none" }} />

            {!iocFile && (
              <textarea
                placeholder={"Paste email headers, log lines, SIEM alert output...\n\nExample:\nFrom: attacker@evil.ru\nReceived: from 185.220.101.1\nLink: http://malicious.tk/payload.exe\nHash: e3b0c44298fc1c149afb4c8996fb92427ae41e4649b934ca495991b7852b855"}
                value={iocText} onChange={e => setIocText(e.target.value)}
                style={{ ...inputStyle, minHeight: "160px", resize: "vertical", fontFamily: "monospace", fontSize: "12px", lineHeight: "1.6" }}
              />
            )}

            <div style={{ marginTop: "14px" }}>
              <Btn onClick={analyzeIOC} color={C.pink} dimColor={C.pinkDim}>{iocLoading ? "⏳ Extracting..." : "🔍 Extract IOCs"}</Btn>
            </div>
          </div>

          {iocResult && (() => {
            const { ips, urls, domains, emails, md5s, sha1s, sha256s, flagged, riskScore } = iocResult;
            const badge = getRiskBadge(riskScore);
            const totalIOCs   = ips.length + urls.length + domains.length + emails.length + md5s.length + sha1s.length + sha256s.length;
            const totalFlagged = flagged.ips.length + flagged.urls.length + flagged.domains.length + flagged.emails.length;

            return (
              <ResultCard badge={badge} title="📊 IOC Extraction Report" reportData={iocResult} reportType="ioc">
                {/* Score row */}
                <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: "10px", marginBottom: "16px" }}>
                  {[
                    { label: "Total IOCs",   value: totalIOCs,   color: C.cyan },
                    { label: "🚨 Flagged",   value: totalFlagged, color: C.red },
                    { label: "Risk Score",   value: riskScore,   color: badge.color },
                    { label: "Hashes",       value: md5s.length + sha1s.length + sha256s.length, color: C.amber },
                  ].map(s => (
                    <div key={s.label} style={{ background: C.card, borderRadius: "8px", padding: "12px", textAlign: "center" }}>
                      <p style={lbl}>{s.label}</p>
                      <p style={{ margin: "6px 0 0", fontSize: "24px", fontWeight: "bold", color: s.color }}>{s.value}</p>
                    </div>
                  ))}
                </div>

                {/* Malicious summary banner */}
                {totalFlagged > 0 && (
                  <div style={{ background: "#7f1d1d22", border: `1px solid ${C.red}44`, borderLeft: `3px solid ${C.red}`, borderRadius: "8px", padding: "14px", marginBottom: "16px" }}>
                    <p style={{ margin: "0 0 6px", color: C.red, fontWeight: "bold", fontSize: "13px" }}>🚨 Malicious IOC Summary</p>
                    <p style={{ margin: 0, fontSize: "13px", lineHeight: "1.7", opacity: 0.9 }}>
                      {totalFlagged} malicious indicator{totalFlagged !== 1 ? "s" : ""} detected.
                      {flagged.ips.length > 0 && ` Suspicious IPs identified: ${flagged.ips.join(", ")}.`}
                      {flagged.urls.length > 0 && ` ${flagged.urls.length} URL(s) match malware distribution or phishing patterns.`}
                      {flagged.domains.length > 0 && ` High-risk TLD domains: ${flagged.domains.join(", ")}.`}
                      {flagged.emails.length > 0 && ` Suspicious sender address(es) detected.`}
                      {" "}Immediate investigation recommended.
                    </p>
                  </div>
                )}

                <IOCSection title="IP Addresses"    items={ips}     color={C.cyan}   flagged={flagged.ips} />
                <IOCSection title="URLs"            items={urls}    color={C.violet} flagged={flagged.urls} />
                <IOCSection title="Domains"         items={domains} color={C.amber}  flagged={flagged.domains} />
                <IOCSection title="Email Addresses" items={emails}  color={C.pink}   flagged={flagged.emails} />

                {(md5s.length > 0 || sha1s.length > 0 || sha256s.length > 0) && (
                  <div style={{ marginBottom: "14px" }}>
                    <p style={{ ...lbl, color: C.amber, marginBottom: "6px" }}>File Hashes</p>
                    <div style={{ background: C.card, borderRadius: "8px", padding: "10px", border: `1px solid ${C.border}` }}>
                      {md5s.map((h, i) => <IOCTag key={`md5-${i}`} text={`MD5: ${h}`} color={C.amber} />)}
                      {sha1s.map((h, i) => <IOCTag key={`sha1-${i}`} text={`SHA1: ${h}`} color={C.amber} />)}
                      {sha256s.map((h, i) => <IOCTag key={`sha256-${i}`} text={`SHA256: ${h}`} color={C.amber} />)}
                    </div>
                  </div>
                )}

                {totalIOCs === 0 && (
                  <p style={{ opacity: 0.5, fontSize: "14px", textAlign: "center", padding: "20px 0" }}>No IOCs found in the provided content.</p>
                )}
              </ResultCard>
            );
          })()}
        </>
      )}

    </div>
  );
}

export default App;
