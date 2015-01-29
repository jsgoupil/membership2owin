using HBTI.ServiceTech.Web.Data;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using System;

namespace HBTI.ServiceTech.Web.Providers
{
    public class SQLMembershipSignInManager : SignInManager<aspnet_Membership, Guid>
    {
        public SQLMembershipSignInManager(SQLMembershipUserManager userManager, IAuthenticationManager authenticationManager)
            : base(userManager, authenticationManager)
        {
        }

        public static SQLMembershipSignInManager Create(IdentityFactoryOptions<SQLMembershipSignInManager> options, IOwinContext context)
        {
            return new SQLMembershipSignInManager(context.GetUserManager<SQLMembershipUserManager>(), context.Authentication);
        }
    }
}