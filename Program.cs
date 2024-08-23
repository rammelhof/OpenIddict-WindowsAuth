using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;
using System;


namespace IdentityServer
{
    public class Program
    {
        public static IConfiguration Configuration;
        public static IServiceProvider ServiceProvider;

        public static void Main(string[] args)
        {
            var builder = CreateHostBuilder(args);

            var app = builder.Build();
            app.Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
            .ConfigureAppConfiguration((hostingContext, config) =>
            {
                config.Sources.Clear();
                config.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
                config.AddEnvironmentVariables();
                if (args != null)
                {
                    config.AddCommandLine(args);
                }
            })
            .ConfigureLogging((context, logging) =>
            {

                logging.ClearProviders();

                var logger = new LoggerConfiguration()
                    .ReadFrom.Configuration(context.Configuration)
                    .CreateLogger();
                logging.AddSerilog(logger);

                logging.SetMinimumLevel(LogLevel.Debug);
            })
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.UseStartup<Startup>();
            });
    }
}
