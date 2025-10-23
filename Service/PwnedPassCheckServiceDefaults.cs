using System.IO;

namespace PwnedPassCheckService;

internal static class PwnedPassCheckServiceDefaults
{
    public const string RootDirectory = @"C:\PwndPassCheck";

    public static string AppSettingsPath => Path.Combine(RootDirectory, "appsettings.json");

    public static string ServiceRunnerPath => Path.Combine(RootDirectory, "PwnedPassCheckServiceRunner.ps1");

    public static string SettingsPath => Path.Combine(RootDirectory, "PwnedPassCheckSettings.psd1");

    public static string AuditLogPath => Path.Combine(RootDirectory, "PwndPassCheckAuditLog.json");
}
