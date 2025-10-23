using System;

namespace PwnedPassCheckService;

public sealed class PwshRunnerOptions
{
    private int _runIntervalMinutes = 30;

    public string PwshPath { get; set; } = "pwsh.exe";

    public string ServiceScriptPath { get; set; } = "PwnedPassCheckServiceRunner.ps1";

    public string? SettingsPath { get; set; }

    public string? AuditLogPath { get; set; }

    public bool Verbose { get; set; }

    public int RunIntervalMinutes
    {
        get => _runIntervalMinutes;
        set => _runIntervalMinutes = value <= 0 ? 30 : value;
    }

    public TimeSpan Interval => TimeSpan.FromMinutes(Math.Clamp(_runIntervalMinutes, 5, 1440));
}
