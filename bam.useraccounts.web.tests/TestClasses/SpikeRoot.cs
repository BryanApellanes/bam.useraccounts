using System.Reflection;
using Bam.UserAccounts.Web.Pages;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Rendering;
using Microsoft.AspNetCore.Components.Routing;

namespace Bam.UserAccounts.Web.Tests.TestClasses;

/// <summary>
/// The test host's root component: a router whose only page assembly is the Razor class
/// library, the way a real host adds the library through <c>AddAdditionalAssemblies</c>.
/// Written in C# so the test project stays a plain SDK project.
/// </summary>
public sealed class SpikeRoot : ComponentBase
{
    private static readonly Assembly[] LibraryAssemblies = { typeof(Spike).Assembly };

    protected override void BuildRenderTree(RenderTreeBuilder builder)
    {
        builder.OpenComponent<Router>(0);
        builder.AddComponentParameter(1, nameof(Router.AppAssembly), typeof(SpikeRoot).Assembly);
        builder.AddComponentParameter(2, nameof(Router.AdditionalAssemblies), LibraryAssemblies);
        builder.AddComponentParameter(3, nameof(Router.Found), (RenderFragment<Microsoft.AspNetCore.Components.RouteData>)Found);
        builder.CloseComponent();
    }

    private static RenderFragment Found(Microsoft.AspNetCore.Components.RouteData routeData)
    {
        return builder =>
        {
            builder.OpenComponent<RouteView>(0);
            builder.AddComponentParameter(1, nameof(RouteView.RouteData), routeData);
            builder.CloseComponent();
        };
    }
}
