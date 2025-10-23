using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace PwnedPassCheckService;

public sealed class PwnedPassCheckWorker : BackgroundService
{
    private readonly ILogger<PwnedPassCheckWorker> _logger;
    private readonly PwshRunnerOptions _options;
    private readonly string _contentRoot;
    private readonly SemaphoreSlim _executionGate = new(1, 1);

    public PwnedPassCheckWorker(
        ILogger<PwnedPassCheckWorker> logger,
        IOptions<PwshRunnerOptions> options,
        IHostEnvironment environment)
    {
        _logger = logger;
        _options = options.Value ?? throw new ArgumentNullException(nameof(options));
        _contentRoot = string.IsNullOrWhiteSpace(environment?.ContentRootPath)
            ? AppContext.BaseDirectory
            : environment.ContentRootPath;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "PwnedPassCheck service starting. Interval: {Interval} minute(s).",
            _options.Interval.TotalMinutes);

        while (!stoppingToken.IsCancellationRequested)
        {
            await RunAuditAsync(stoppingToken);

            try
            {
                await Task.Delay(_options.Interval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _logger.LogInformation("PwnedPassCheck service stopping.");
    }

    private async Task RunAuditAsync(CancellationToken stoppingToken)
    {
        if (!await _executionGate.WaitAsync(0, stoppingToken))
        {
            _logger.LogWarning("Previous audit is still running; skipping this interval.");
            return;
        }

        try
        {
            var scriptPath = ResolveRelativePath(_options.ServiceScriptPath);
            if (!File.Exists(scriptPath))
            {
                _logger.LogError("Runner script '{ScriptPath}' was not found.", scriptPath);
                return;
            }

            var pwshPath = string.IsNullOrWhiteSpace(_options.PwshPath) ? "pwsh.exe" : _options.PwshPath;
            var workingDirectory = Path.GetDirectoryName(scriptPath);
            var startInfo = new ProcessStartInfo
            {
                FileName = pwshPath,
                WorkingDirectory = string.IsNullOrWhiteSpace(workingDirectory) ? _contentRoot : workingDirectory,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            startInfo.ArgumentList.Add("-NoProfile");
            startInfo.ArgumentList.Add("-ExecutionPolicy");
            startInfo.ArgumentList.Add("Bypass");
            startInfo.ArgumentList.Add("-File");
            startInfo.ArgumentList.Add(scriptPath);

            if (!string.IsNullOrWhiteSpace(_options.SettingsPath))
            {
                startInfo.ArgumentList.Add("-SettingsPath");
                startInfo.ArgumentList.Add(_options.SettingsPath);
            }

            if (!string.IsNullOrWhiteSpace(_options.AuditLogPath))
            {
                startInfo.ArgumentList.Add("-AuditLogPath");
                startInfo.ArgumentList.Add(_options.AuditLogPath);
            }

            if (_options.Verbose)
            {
                startInfo.ArgumentList.Add("-Verbose");
            }

            using var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
            var standardOutput = new StringBuilder();
            var standardError = new StringBuilder();

            process.OutputDataReceived += (_, args) =>
            {
                if (!string.IsNullOrEmpty(args.Data))
                {
                    standardOutput.AppendLine(args.Data);
                }
            };

            process.ErrorDataReceived += (_, args) =>
            {
                if (!string.IsNullOrEmpty(args.Data))
                {
                    standardError.AppendLine(args.Data);
                }
            };

            var runStarted = DateTimeOffset.Now;
            _logger.LogInformation("Starting Get-PwnedADUserPassword run at {StartTime:u}.", runStarted);

            if (!process.Start())
            {
                _logger.LogError("Failed to start '{PwshPath}'.", pwshPath);
                return;
            }

            using var registration = stoppingToken.Register(() =>
            {
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Unable to terminate pwsh process during cancellation.");
                }
            });

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            await process.WaitForExitAsync(stoppingToken);

            var exitCode = process.ExitCode;
            var runDuration = DateTimeOffset.Now - runStarted;

            if (standardOutput.Length > 0)
            {
                _logger.LogInformation("pwsh output:{NewLine}{Output}", Environment.NewLine, standardOutput.ToString().TrimEnd());
            }

            if (standardError.Length > 0)
            {
                _logger.LogWarning("pwsh errors:{NewLine}{Output}", Environment.NewLine, standardError.ToString().TrimEnd());
            }

            if (exitCode == 0)
            {
                _logger.LogInformation("Get-PwnedADUserPassword completed successfully in {Duration}.", runDuration);
            }
            else
            {
                _logger.LogError("Get-PwnedADUserPassword exited with code {ExitCode} after {Duration}.", exitCode, runDuration);
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Audit run cancelled.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error while running Get-PwnedADUserPassword.");
        }
        finally
        {
            _executionGate.Release();
        }
    }

    private string ResolveRelativePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return Path.Combine(_contentRoot, "PwnedPassCheckServiceRunner.ps1");
        }

        if (Path.IsPathRooted(path))
        {
            return path;
        }

        return Path.Combine(_contentRoot, path);
    }
}
