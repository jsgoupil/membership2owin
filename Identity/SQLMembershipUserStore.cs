using HBTI.ServiceTech.Web.Data;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;

namespace HBTI.ServiceTech.Web.Providers
{
    public class SQLMembershipUserStore :
        IUserStore<aspnet_Membership, Guid>,
        IUserLockoutStore<aspnet_Membership, Guid>,
        IUserPasswordStore<aspnet_Membership, Guid>,
        IUserTwoFactorStore<aspnet_Membership, Guid>,
        IUserRoleStore<aspnet_Membership, Guid>,
        IUserEmailStore<aspnet_Membership, Guid>,
        IQueryableUserStore<aspnet_Membership, Guid>
    {
        protected HBTI_EF db_context;
        protected string loweredApplicationName;

        public bool DisposeContext
        {
            get;
            set;
        }

        public SQLMembershipUserStore(HBTI_EF db_context, string loweredApplicationName)
        {
            this.db_context = db_context;
            this.loweredApplicationName = loweredApplicationName;
            this.DisposeContext = true;
        }

        public static SQLMembershipUserStore Create(IdentityFactoryOptions<SQLMembershipUserStore> options, IOwinContext context)
        {
            return new SQLMembershipUserStore(context.Get<HBTI_EF>(), "/");
        }

        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (this.DisposeContext && disposing && this.db_context != null)
            {
                this.db_context.Dispose();
            }

            this.db_context = null;
        }

        public virtual async Task CreateAsync(aspnet_Membership user)
        {
            db_context.Entry(user).State = EntityState.Added;
            await db_context.SaveChangesAsync();
        }

        public virtual async Task UpdateAsync(aspnet_Membership user)
        {
            db_context.Entry(user).State = EntityState.Modified;
            await db_context.SaveChangesAsync();
        }

        public virtual async Task DeleteAsync(aspnet_Membership user)
        {
            db_context.Entry(user).State = EntityState.Deleted;
            await db_context.SaveChangesAsync();
        }

        public virtual async Task<aspnet_Membership> FindByIdAsync(Guid userId)
        {
            return await db_context.aspnet_Membership
                .Include("aspnet_Users")
                .Where(m => m.aspnet_Applications.LoweredApplicationName == loweredApplicationName)
                .Where(m => m.UserId == userId)
                .FirstOrDefaultAsync();
        }

        public virtual async Task<aspnet_Membership> FindByNameAsync(string userName)
        {
            var lowercaseUserName = userName.ToLower();
            return await db_context.aspnet_Membership
                .Include("aspnet_Users")
                .Where(m => m.aspnet_Applications.LoweredApplicationName == loweredApplicationName)
                .Where(m => m.aspnet_Users.LoweredUserName == lowercaseUserName)
                .FirstOrDefaultAsync();
        }

        public virtual Task<int> GetAccessFailedCountAsync(aspnet_Membership user)
        {
            return Task.FromResult(user.FailedPasswordAttemptCount);
        }

        public virtual Task<bool> GetLockoutEnabledAsync(aspnet_Membership user)
        {
            // LockoutEnabled doesn't mean it's currently locked out.
            // It means if the user is allowed to be locked out.
            // Admin probably shouldn't be locked out otherwise you will end up
            // having to go manually in the database to unlock yourself.
            return Task.FromResult(true);
        }

        public virtual Task<DateTimeOffset> GetLockoutEndDateAsync(aspnet_Membership user)
        {
            // There is no concept of end date in Membership.
            // The user is locked out indefinitely.
            // The FailedPasswordAttemptWindowStart was used to count the number of Invalid password attempt
            // Within a period of time. The number would then reset to 0 if we go over the passwordAttemptWindow limit.
            // We will change this behavior and lock them out for the default period of time.
            // We repurpose this column and use it as when will the user be unlocked.
            // However, if the IsLockedOut is set to 1, then we tell that this user is locked forever
            if (user.IsLockedOut)
            {
                return Task.FromResult(new DateTimeOffset(DateTime.UtcNow.AddYears(1)));
            }

            return Task.FromResult(new DateTimeOffset(DateTime.SpecifyKind(user.FailedPasswordAttemptWindowStart, DateTimeKind.Utc)));
        }

        public virtual Task<int> IncrementAccessFailedCountAsync(aspnet_Membership user)
        {
            user.FailedPasswordAttemptCount++;
            return Task.FromResult(user.FailedPasswordAttemptCount);
        }

        public virtual Task ResetAccessFailedCountAsync(aspnet_Membership user)
        {
            user.FailedPasswordAttemptCount = 0;
            return Task.FromResult(0);
        }

        public virtual Task SetLockoutEnabledAsync(aspnet_Membership user, bool enabled)
        {
            // There is no concept allowing if a user can be locked out or not.
            // If you want to add your own, put some logic here by using an existing column.
            // Or create your own column.
            return Task.FromResult(0);
        }

        public virtual Task SetLockoutEndDateAsync(aspnet_Membership user, DateTimeOffset lockoutEnd)
        {
            user.FailedPasswordAttemptWindowStart = lockoutEnd.UtcDateTime;
            user.LastLockoutDate = DateTime.UtcNow;
            return Task.FromResult(0);
        }

        public virtual Task<string> GetPasswordHashAsync(aspnet_Membership user)
        {
            return Task.FromResult(string.Format("{0}|{1}|{2}", user.Password, user.PasswordFormat, user.PasswordSalt));
        }

        public virtual Task<bool> HasPasswordAsync(aspnet_Membership user)
        {
            return Task.FromResult(!string.IsNullOrWhiteSpace(user.Password));
        }

        public virtual Task SetPasswordHashAsync(aspnet_Membership user, string passwordHash)
        {
            user.Password = passwordHash;
            user.PasswordFormat = 4;
            user.PasswordSalt = string.Empty;
            user.LastPasswordChangedDate = DateTime.UtcNow;
            return Task.FromResult(0);
        }

        public virtual Task<bool> GetTwoFactorEnabledAsync(aspnet_Membership user)
        {
            return Task.FromResult(false);
        }

        public virtual Task SetTwoFactorEnabledAsync(aspnet_Membership user, bool enabled)
        {
            throw new NotImplementedException();
        }

        public virtual Task AddToRoleAsync(aspnet_Membership user, string roleName)
        {
            var role = GetRole(user, roleName);

            if (role == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, "The role {0} doesn't exist.", roleName));
            }

            user.aspnet_Users.aspnet_Roles.Add(role);
            return Task.FromResult(0);
        }

        public virtual Task<IList<string>> GetRolesAsync(aspnet_Membership user)
        {
            return Task.FromResult(user.aspnet_Users.aspnet_Roles.Select(r => r.RoleName).ToList() as IList<string>);
        }

        public virtual Task<bool> IsInRoleAsync(aspnet_Membership user, string roleName)
        {
            return Task.FromResult(GetRole(user, roleName) != null);
        }

        public virtual Task RemoveFromRoleAsync(aspnet_Membership user, string roleName)
        {
            var role = GetRole(user, roleName);
            if (role != null)
            {
                user.aspnet_Users.aspnet_Roles.Remove(role);
            }

            return Task.FromResult(0);
        }

        public virtual async Task<aspnet_Membership> FindByEmailAsync(string email)
        {
            var loweredEmail = email.ToLower();
            return await db_context.aspnet_Membership
                .Include("aspnet_Users")
                .Where(m => m.aspnet_Applications.LoweredApplicationName == loweredApplicationName)
                .Where(m => m.LoweredEmail == loweredEmail)
                .FirstOrDefaultAsync();
        }

        public virtual Task<string> GetEmailAsync(aspnet_Membership user)
        {
            return Task.FromResult(user.Email);
        }

        public virtual Task<bool> GetEmailConfirmedAsync(aspnet_Membership user)
        {
            return Task.FromResult(user.IsApproved);
        }

        public virtual Task SetEmailAsync(aspnet_Membership user, string email)
        {
            user.Email = email;
            user.LoweredEmail = email.ToLower();
            return Task.FromResult(0);
        }

        public virtual Task SetEmailConfirmedAsync(aspnet_Membership user, bool confirmed)
        {
            user.IsApproved = confirmed;
            return Task.FromResult(0);
        }

        public virtual IQueryable<aspnet_Membership> Users
        {
            get
            {
                return db_context.aspnet_Membership;
            }
        }

        protected virtual aspnet_Roles GetRole(aspnet_Membership user, string roleName)
        {
            var loweredRoleName = roleName.ToLower();
            return user.aspnet_Users.aspnet_Roles.FirstOrDefault(r => r.LoweredRoleName == loweredRoleName);
        }
    }
}