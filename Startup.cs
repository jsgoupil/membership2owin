using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(HBTI.ServiceTech.Web.Startup))]

namespace HBTI.ServiceTech.Web
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}