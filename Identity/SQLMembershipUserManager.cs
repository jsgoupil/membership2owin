using HBTI.ServiceTech.Web.Data;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using System;

namespace HBTI.ServiceTech.Web.Providers
{
    public class SQLMembershipUserManager : UserManager<aspnet_Membership, Guid>
    {
        public SQLMembershipUserManager(SQLMembershipUserStore store)
            : base(store)
        {
            this.PasswordHasher = new SQLMembershipPasswordHasher();
        }

        protected new internal SQLMembershipUserStore Store
        {
            get
            {
                return (SQLMembershipUserStore)base.Store;
            }
        }

        public static SQLMembershipUserManager Create(IdentityFactoryOptions<SQLMembershipUserManager> options, IOwinContext context)
        {
            var manager = new SQLMembershipUserManager(context.Get<SQLMembershipUserStore>());

            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider = new DataProtectorTokenProvider<aspnet_Membership, Guid>(dataProtectionProvider.Create("ASP.NET Identity"));
            }

            return manager;
        }
    }
}