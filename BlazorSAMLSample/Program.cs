using BlazorSAMLSample.Areas.Identity;
using BlazorSAMLSample.Data;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.StaticFiles.Infrastructure;
using Microsoft.EntityFrameworkCore;

using Sustainsys.Saml2;
using Sustainsys.Saml2.AspNetCore2;
using Sustainsys.Saml2.Metadata;
using System.Configuration;
using System.Security.Cryptography.X509Certificates;

namespace BlazorSAMLSample
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
            builder.Services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(connectionString));
            builder.Services.AddDatabaseDeveloperPageExceptionFilter();
            builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
                .AddEntityFrameworkStores<ApplicationDbContext>();
            builder.Services.AddRazorPages();
            builder.Services.AddServerSideBlazor();
            builder.Services.AddScoped<AuthenticationStateProvider, RevalidatingIdentityAuthenticationStateProvider<IdentityUser>>();
            builder.Services.AddSingleton<WeatherForecastService>();
            builder.Services.AddMvc(options => options.Filters.Add(new AuthorizeFilter()));

            builder.Services.Configure<CookiePolicyOptions>(opt =>
            {
                opt.MinimumSameSitePolicy = SameSiteMode.Strict;
                opt.HttpOnly = HttpOnlyPolicy.None;
                opt.Secure = CookieSecurePolicy.None;
                // opt.Secure = CookieSecurePolicy.Always;
                opt.OnAppendCookie = cookieContext =>
                    CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
                opt.OnDeleteCookie = cookieContext =>
                    CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);

            });

            void CheckSameSite(HttpContext httpContext, CookieOptions options)
            {
                if (options.SameSite == SameSiteMode.None)
                {
                    var userAgent = httpContext.Request.Headers["User-Agent"].ToString();
                    //if (MyUserAgentDetectionLib.DisallowsSameSiteNone(userAgent))
                    //{
                    //    options.SameSite = SameSiteMode.Unspecified;
                    //}
                    options.SameSite = SameSiteMode.Unspecified;
                }
            }

            builder.Services.AddAuthentication(opt =>
            {
                // Default scheme that maintains session is cookies.
                // opt.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                opt.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;

                opt.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

                // If there's a challenge to sign in, use the Saml2 scheme.
                // opt.DefaultChallengeScheme = Saml2Defaults.Scheme;
                opt.DefaultChallengeScheme = Saml2Defaults.Scheme;
            })
            .AddCookie(opt =>
            {
                opt.Cookie.SameSite = SameSiteMode.None;
                opt.Cookie.HttpOnly = true;
                // opt.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                opt.Cookie.SecurePolicy = CookieSecurePolicy.None;
                opt.Cookie.SameSite = SameSiteMode.Lax;
                opt.Cookie.IsEssential = true;
            })
            .AddSaml2(opt =>
            {
                // Set up our EntityId, this is our application.
                // opt.SPOptions.EntityId = new EntityId("https://localhost:44373/Saml2");

                opt.SPOptions = new Sustainsys.Saml2.Configuration.SPOptions()
                {
                    AuthenticateRequestSigningBehavior = Sustainsys.Saml2.Configuration.SigningBehavior.Never,
                    EntityId = new EntityId("https://localhost:44373/Saml2"),
                    MinIncomingSigningAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
                };

                // Single logout messages should be signed according to the SAML2 standard, so we need
                // to add a certificate for our app to sign logout messages with to enable logout functionality.
                string certFile = string.Format("{0}\\{1}", System.IO.Directory.GetCurrentDirectory(), "Sustainsys.Saml2.Tests.pfx");
                opt.SPOptions.ServiceCertificates.Add(new X509Certificate2("Sustainsys.Saml2.Tests.pfx"));

                // Add an identity provider.
                opt.IdentityProviders.Add(new IdentityProvider(
                    // The identityprovider's entity id.
                    new EntityId("https://portal.trustlogin.com/asiasystem/idp/96857/saml"),
                    opt.SPOptions)
                {
                    // Load config parameters from metadata, using the Entity Id as the metadata address.
                    // LoadMetadata = true,
                    MetadataLocation = "your-metadata.xml",
                    AllowUnsolicitedAuthnResponse = true,
                    LoadMetadata = true
                });
            });

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseMigrationsEndPoint();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();

            app.UseStaticFiles();

            app.UseRouting();
            app.UseAuthentication(); ;

            app.UseCookiePolicy();
            app.UseAuthentication();

            app.UseAuthorization();

            app.MapControllers();
            app.MapBlazorHub();
            app.MapFallbackToPage("/_Host");

            app.Run();
        }
    }
}