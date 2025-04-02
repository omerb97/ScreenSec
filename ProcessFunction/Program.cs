using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;

var host = new HostBuilder()
    .ConfigureFunctionsWebApplication()
    .ConfigureServices(services =>
    {
        // Register HttpClient using the HttpClient factory.
        services.AddHttpClient();
    })
    .Build();

host.Run();
