using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System.Web.Mvc;

namespace HBTI.ServiceTech.Web
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            app.CreatePerOwinContext<HBTIUserStore>(SQLMembershipUserStore.Create);
            app.CreatePerOwinContext<HBTIUserManager>(SQLMembershipUserManager.Create);
            app.CreatePerOwinContext<HBTISignInManager>(SQLMembershipSignInManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/LogOn")
            });
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);
        }
    }
}