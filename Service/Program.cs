using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using PwnedPassCheckService;

var host = Host.CreateDefaultBuilder(args)
    .ConfigureAppConfiguration((context, config) =>
    {
        config.AddJsonFile(
            path: PwnedPassCheckServiceDefaults.AppSettingsPath,
            optional: true,
            reloadOnChange: true);
    })
    .UseWindowsService(options =>
    {
        options.ServiceName = "PwnedPassCheckService";
    })
    .ConfigureServices((context, services) =>
    {
        services.Configure<PwshRunnerOptions>(context.Configuration.GetSection("Service"));
        services.AddHostedService<PwnedPassCheckWorker>();

        services.Configure<HostOptions>(options =>
        {
            options.BackgroundServiceExceptionBehavior = BackgroundServiceExceptionBehavior.Ignore;
        });
    })
    .ConfigureLogging(logging =>
    {
        logging.ClearProviders();
        logging.AddSimpleConsole();
        logging.AddEventLog(settings =>
        {
            settings.SourceName = "PwnedPassCheckService";
        });
    })
    .Build();

await host.RunAsync();
