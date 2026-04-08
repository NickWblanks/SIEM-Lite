using ParsingEngine.Models;

namespace ParsingEngine.Services
{
    public class ThreatDetectionService
    {
        public LogEvent AnalyzeLog(LogEvent log)
        {
            // Default safe state
            log.ThreatLevel = "Low";
            log.RuleTriggered = "None";

            // ==========================================
            // LAYER 7: APPLICATION RULES (HTTP / WEB)
            // ==========================================

            // Rule 1: Known Malicious Payloads (SQLi, XSS, Path Traversal)
            if (!string.IsNullOrEmpty(log.Endpoint) && 
                (log.Endpoint.Contains("../") || log.Endpoint.Contains("<script>") || log.Endpoint.Contains("OR '1'='1")))
            {
                log.ThreatLevel = "High";
                log.RuleTriggered = "Malicious Payload Detected (SQLi/XSS/Traversal)";
                return log; 
            }

            // Rule 2: Failed Authentication / Unauthorized Access
            if (log.Status == 401 || log.Status == 403)
            {
                log.ThreatLevel = "Medium";
                log.RuleTriggered = "Unauthorized Access Attempt";
                return log;
            }

            // Rule 3: Suspicious Tooling (Nmap, Curl scripts)
            if (!string.IsNullOrEmpty(log.UserAgent) && 
                (log.UserAgent.Contains("curl") || log.UserAgent.Contains("Nmap") || log.UserAgent == "-"))
            {
                log.ThreatLevel = "Low-Medium";
                log.RuleTriggered = "Automated Tooling / Script Detected";
                return log;
            }

            // ==========================================
            // LAYER 4: TRANSPORT RULES (TCP / UDP)
            // ==========================================

            // Rule 4: Sensitive Port Exposure (SSH, RDP, Telnet)
            if (log.DestPort == 22 || log.DestPort == 3389 || log.DestPort == 23)
            {
                log.ThreatLevel = "High";
                string service = log.DestPort == 22 ? "SSH" : (log.DestPort == 3389 ? "RDP" : "Telnet");
                log.RuleTriggered = $"Suspicious access attempt to sensitive port ({service})";
                return log;
            }

            // Rule 5: Known Malware / Command & Control (C2) Ports
            // 4444 = Metasploit default, 6667 = Old school IRC Botnets
            if (log.DestPort == 4444 || log.SrcPort == 4444 || log.DestPort == 6667)
            {
                log.ThreatLevel = "High";
                log.RuleTriggered = "Traffic detected on known Malware/C2 port";
                return log;
            }

            // Rule 6: Data Exfiltration / Amplification Anomalies
            // Massive UDP payloads are often used for DDoS amplification or data theft
            if (log.Protocol == "UDP" && log.Length > 5000)
            {
                log.ThreatLevel = "Medium";
                log.RuleTriggered = "Anomalously large UDP payload detected";
                return log;
            }

            return log; // Return the safe log if it passes all filters
        }
    }
}