using Microsoft.AspNetCore.Mvc;
using ParsingEngine.Models;
using ParsingEngine.Services;
using Elastic.Clients.Elasticsearch;

var builder = WebApplication.CreateBuilder(args);

// 1. Register our Threat Detection Service
builder.Services.AddSingleton<ThreatDetectionService>();

// 2. Configure and Register the Elasticsearch Client
// (Since we disabled xpack.security in Docker, we don't need a password here)
var elasticSettings = new ElasticsearchClientSettings(new Uri("http://localhost:9200"))
    .DefaultIndex("siem-logs"); // Tell it to put everything in the "siem-logs" index by default

var elasticClient = new ElasticsearchClient(elasticSettings);
builder.Services.AddSingleton(elasticClient);

var app = builder.Build();

// 3. Define the HTTP POST Endpoint (Notice we added 'async' and injected the 'esClient')
app.MapPost("/api/ingest", async ([FromBody] LogEvent incomingLog, ThreatDetectionService threatService, ElasticsearchClient esClient) =>
{
    // A. Analyze the log
    var enrichedLog = threatService.AnalyzeLog(incomingLog);

    // B. Console Logging
    if (enrichedLog.ThreatLevel == "High")
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"[CRITICAL ALERT] {enrichedLog.RuleTriggered} from IP: {enrichedLog.IpAddress}");
        Console.ResetColor();
    }
    else if (enrichedLog.ThreatLevel == "Medium" || enrichedLog.ThreatLevel == "Low-Medium")
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"[WARNING] {enrichedLog.RuleTriggered} from IP: {enrichedLog.IpAddress}");
        Console.ResetColor();
    }
    else
    {
        Console.WriteLine($"[INFO] Routine traffic processed from {enrichedLog.IpAddress}");
    }

    // C. Push the enriched log to Elasticsearch
    var indexResponse = await esClient.IndexAsync(enrichedLog);
    
    if (!indexResponse.IsValidResponse)
    {
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine($"[DB ERROR] Failed to save log to Elasticsearch: {indexResponse.DebugInformation}");
        Console.ResetColor();
    }

    // D. Respond to the Python script
    return Results.Ok(new { 
        message = "Log ingested and saved to DB", 
        threatLevel = enrichedLog.ThreatLevel 
    });
});

app.Run("http://localhost:5000");