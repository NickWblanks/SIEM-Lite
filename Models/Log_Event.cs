using System;
using System.Text.Json.Serialization;

namespace ParsingEngine.Models
{
    public class LogEvent
    {
        // --- Universal Fields (Always Present) ---
        [JsonPropertyName("timestamp")]
        public DateTime Timestamp { get; set; }

        [JsonPropertyName("ip")]
        public string IpAddress { get; set; } = string.Empty;

        [JsonPropertyName("message")]
        public string Message { get; set; } = string.Empty;


        // --- Test Mode Fields (Nullable) ---
        [JsonPropertyName("method")]
        public string? Method { get; set; }

        [JsonPropertyName("endpoint")]
        public string? Endpoint { get; set; }

        [JsonPropertyName("status")]
        public int? Status { get; set; }

        [JsonPropertyName("user_agent")]
        public string? UserAgent { get; set; }


        // --- Live Mode Fields (Nullable) ---
        [JsonPropertyName("dest_ip")]
        public string? DestIp { get; set; }

        [JsonPropertyName("protocol")]
        public string? Protocol { get; set; }

        [JsonPropertyName("length")]
        public int? Length { get; set; }

        [JsonPropertyName("src_port")]
        public int? SrcPort { get; set; }

        [JsonPropertyName("dest_port")]
        public int? DestPort { get; set; }


        // --- SIEM Enrichment Fields (Added by this C# Engine) ---
        public string ThreatLevel { get; set; } = "Low";
        public string? RuleTriggered { get; set; }
    }
}