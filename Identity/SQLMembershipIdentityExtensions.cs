using Microsoft.AspNet.Identity;
using System;
using System.Security.Claims;
using System.Security.Principal;

namespace HBTI.ServiceTech.Web.Providers
{
    public static class SQLMembershipIdentityExtensions
    {
        public static Guid GetUserGuidId(this IIdentity identity)
        {
            if (identity == null)
            {
                throw new ArgumentNullException("identity");
            }

            ClaimsIdentity claimsIdentity = identity as ClaimsIdentity;
            if (claimsIdentity != null)
            {
                return Guid.Parse(claimsIdentity.FindFirstValue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"));
            }

            return Guid.Empty;
        }
    }
}