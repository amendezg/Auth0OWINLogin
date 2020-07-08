using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using System.Configuration;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

[assembly: OwinStartup(typeof(Auth0OwinLogin.Startup))]

namespace Auth0OwinLogin
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=316888

            // Configure Auth0 parameters
            string auth0Domain = ConfigurationManager.AppSettings["auth0:Domain"];
            string auth0ClientId = ConfigurationManager.AppSettings["auth0:ClientId"];
            string auth0ClientSecret = ConfigurationManager.AppSettings["auth0:ClientSecret"];
            string auth0RedirectUri = ConfigurationManager.AppSettings["auth0:RedirectUri"];
            string auth0PostLogoutRedirectUri = ConfigurationManager.AppSettings["auth0:PostLogoutRedirectUri"];

            // https://docs.microsoft.com/en-us/previous-versions/aspnet/mt152170(v%3Dvs.113)
            // Called by middleware to change the name of the AuthenticationType that external middleware should use when the browser navigates back to their return url.
            // Namespace: Microsoft.Owin.Security
            // Parameters
            //  authenticationType
            //      Type: System.String 
            //      AuthenticationType that external middleware should sign in as.
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType); // CookieAuthenticationDefaults.AuthenticationType = "Cookies"

            // https://docs.microsoft.com/en-us/previous-versions/aspnet/dn782616(v%3Dvs.113)
            // Adds a cookie-based authentication middleware to your web application pipeline.
            // Parameters:
            //  options
            //      Type: Microsoft.Owin.Security.Cookies.CookieAuthenticationOptions
            //      An options class that controls the middleware behavior
            app.UseCookieAuthentication(new CookieAuthenticationOptions {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType, // CookieAuthenticationDefaults.AuthenticationType = "Cookies"
                LoginPath = new PathString("/Account/Login"),
                // Configure SameSite as needed for your app. Lax works well for most scenarios here but
                // you may want to set SameSiteMode.None for HTTPS
                CookieSameSite = SameSiteMode.Lax, // https://docs.microsoft.com/en-us/aspnet/samesite/owin-samesite
                CookieSecure = CookieSecureOption.SameAsRequest // https://docs.microsoft.com/en-us/previous-versions/aspnet/mt152267(v%3Dvs.113)
            });

            // Configure Auth0 Authentication
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions {
                AuthenticationType = "Auth0",
                Authority = string.Format("https://{0}", auth0Domain),
                ClientId = auth0ClientId,
                ClientSecret = auth0ClientSecret,
                RedirectUri = auth0RedirectUri,
                PostLogoutRedirectUri = auth0PostLogoutRedirectUri,
                ResponseType = OpenIdConnectResponseType.CodeIdToken,
                Scope = "openid profile",
                TokenValidationParameters = new TokenValidationParameters {
                    NameClaimType = "name"
                },
                Notifications = new OpenIdConnectAuthenticationNotifications {
                    RedirectToIdentityProvider = notification => {
                        if (notification.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout) {
                            var logoutUri = string.Format("https://{0}/v2/logout?client_id={1}", auth0Domain, auth0ClientId);

                            var postLogoutUri = notification.ProtocolMessage.PostLogoutRedirectUri;
                            if (!string.IsNullOrEmpty(postLogoutUri)) {
                                if (postLogoutUri.StartsWith("/")) {
                                    //Transform to absolute
                                    var request = notification.Request;
                                    postLogoutUri = request.Scheme + "://" + request.Host + request.PathBase + postLogoutUri;
                                }
                                logoutUri += string.Format("&returnTo={0}", Uri.EscapeDataString(postLogoutUri));
                            }
                            notification.Response.Redirect(logoutUri);
                            notification.HandleResponse();
                        }
                        return Task.FromResult(0);
                    }
                }
            });
        }
    }
}
