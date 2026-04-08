@echo off
setlocal
title SIEM-Lite Deployment Hub

echo ======================================================
echo           SIEM-LITE: STARTING INFRASTRUCTURE
echo ======================================================

:: 1. Start Docker Containers
echo [1/3] Spinning up Elasticsearch, Kibana, and C# Engine...
docker-compose up -d --build

:: 2. Wait for the API to be reachable
echo [2/3] Waiting for C# Engine to accept connections...
:check_api
curl -s http://localhost:5000 >nul
if %errorlevel% neq 0 (
    echo     ...Waiting for API to boot...
    timeout /t 3 /nobreak >nul
    goto check_api
)
echo [SUCCESS] C# Engine is Online!

:: 3. Launch the Python Sensor
echo [3/3] Launching Live Network Sniffer...
start "SIEM-Lite: Live Sensor" cmd /k "python Log_Generator.py --mode live"

echo ======================================================
echo SIEM-Lite is now FULLY OPERATIONAL!
echo ------------------------------------------------------
echo Dashboard: http://localhost:5601
echo API Debug: http://localhost:5000
echo ======================================================
echo Press any key to shutdown all services...
pause >nul

echo Shutting down containers...
docker-compose down
echo Done.
pause