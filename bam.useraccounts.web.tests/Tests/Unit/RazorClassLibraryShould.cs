using System.Net;
using Bam.DependencyInjection;
using Bam.Test;
using Bam.UserAccounts.Web.Pages;
using Bam.UserAccounts.Web.Tests.TestClasses;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Bam.UserAccounts.Web.Tests.Unit;

[UnitTestMenu("RazorClassLibrary Should", Selector = "acrl")]
public class RazorClassLibraryShould : UnitTestMenuContainer
{
    public RazorClassLibraryShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    [UnitTest]
    public void ServeItsPagesAndStaticAssetsFromAHost()
    {
        When.A<WebApplicationBuilder>("hosts the class library's page and browser module on Kestrel",
            () =>
            {
                WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions
                {
                    EnvironmentName = Environments.Development,
                });
                builder.Logging.ClearProviders();
                builder.WebHost.UseUrls("http://127.0.0.1:0");
                builder.Services.AddRazorComponents();
                return builder;
            },
            (builder) =>
            {
                WebApplication app = builder.Build();
                app.UseStaticFiles();
                app.UseAntiforgery();
                app.MapRazorComponents<SpikeRoot>().AddAdditionalAssemblies(typeof(Spike).Assembly);
                app.StartAsync().GetAwaiter().GetResult();
                try
                {
                    using HttpClient client = new HttpClient { BaseAddress = new Uri(app.Urls.First()) };
                    using HttpResponseMessage page = client.GetAsync("/account/spike").GetAwaiter().GetResult();
                    string pageBody = page.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    using HttpResponseMessage module = client.GetAsync("/_content/bam.useraccounts.web/passkeys.js").GetAwaiter().GetResult();
                    string moduleBody = module.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    return new SpikeOutcome(page.StatusCode, pageBody, module.StatusCode, module.Content.Headers.ContentType?.MediaType, moduleBody);
                }
                finally
                {
                    app.StopAsync().GetAwaiter().GetResult();
                }
            })
            .TheTest
            .ShouldPass<SpikeOutcome>((because, outcome) =>
            {
                because.ItsTrue($"the library's routable page renders through the host router ({outcome.PageStatus})", outcome.PageStatus == HttpStatusCode.OK);
                because.ItsTrue("the page body is the library's markup", outcome.PageBody.Contains("bam.useraccounts.web spike", StringComparison.Ordinal));
                because.ItsTrue($"the library's wwwroot module is served under _content ({outcome.ModuleStatus})", outcome.ModuleStatus == HttpStatusCode.OK);
                because.ItsTrue($"the module is served as JavaScript ({outcome.ModuleMediaType})", outcome.ModuleMediaType == "text/javascript");
                because.ItsTrue("the module body is the library's file", outcome.ModuleBody.Contains("export const version", StringComparison.Ordinal));
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    private sealed record SpikeOutcome(HttpStatusCode PageStatus, string PageBody, HttpStatusCode ModuleStatus, string? ModuleMediaType, string ModuleBody);
}
