@echo off
rem Runs the Go verifier built for this machine against the fixtures in this folder, or against the paths given.
set "d=%~dp0"
set "arch=amd64"
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "arch=arm64"
if /i "%PROCESSOR_ARCHITEW6432%"=="ARM64" set "arch=arm64"
if "%~1"=="" ("%d%bin\windows-%arch%\atx-verify.exe" "%d%fixtures") else ("%d%bin\windows-%arch%\atx-verify.exe" %*)
