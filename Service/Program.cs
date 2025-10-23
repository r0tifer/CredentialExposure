using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

var host = Host.CreateDefaultBuilder(args)
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
