using Microsoft.AspNet.Identity;
using System;
using System.Security.Cryptography;
using System.Text;

namespace HBTI.ServiceTech.Web.Providers
{
    public class SQLMembershipPasswordHasher : PasswordHasher
    {
        public override string HashPassword(string password)
        {
            return base.HashPassword(password);
        }

        public override PasswordVerificationResult VerifyHashedPassword(string hashedPassword, string providedPassword)
        {
            var passwordProperties = hashedPassword.Split('|');
            var passwordHash = passwordProperties.Length == 3 ? passwordProperties[0] : hashedPassword;
            var passwordFormat = passwordProperties.Length == 3 ? int.Parse(passwordProperties[1]) : 0;

            if ((passwordProperties.Length != 3) || (passwordFormat == 4)) // Made up number for new format
            {
                return base.VerifyHashedPassword(passwordHash, providedPassword);
            }
            else
            {
                var salt = passwordProperties[2];
                if (String.Equals(EncryptPassword(providedPassword, passwordFormat, salt), passwordHash, StringComparison.CurrentCultureIgnoreCase))
                {
                    return PasswordVerificationResult.SuccessRehashNeeded;
                }

                return PasswordVerificationResult.Failed;
            }
        }

        // This is copied from the existing SQL providers and is provided only for back-compat.
        private string EncryptPassword(string pass, int passwordFormat, string salt)
        {
            if (passwordFormat == 0) // MembershipPasswordFormat.Clear
            {
                return pass;
            }

            var bIn = Encoding.Unicode.GetBytes(pass);
            var bSalt = Convert.FromBase64String(salt);
            byte[] bRet = null;

            if (passwordFormat == 1) // MembershipPasswordFormat.Hashed 
            {
                var hm = HashAlgorithm.Create("SHA1");
                if (hm is KeyedHashAlgorithm)
                {
                    var kha = (KeyedHashAlgorithm)hm;
                    if (kha.Key.Length == bSalt.Length)
                    {
                        kha.Key = bSalt;
                    }
                    else if (kha.Key.Length < bSalt.Length)
                    {
                        var bKey = new byte[kha.Key.Length];
                        Buffer.BlockCopy(bSalt, 0, bKey, 0, bKey.Length);
                        kha.Key = bKey;
                    }
                    else
                    {
                        var bKey = new byte[kha.Key.Length];
                        for (var iter = 0; iter < bKey.Length; )
                        {
                            var len = Math.Min(bSalt.Length, bKey.Length - iter);
                            Buffer.BlockCopy(bSalt, 0, bKey, iter, len);
                            iter += len;
                        }

                        kha.Key = bKey;
                    }

                    bRet = kha.ComputeHash(bIn);
                }
                else
                {
                    var bAll = new byte[bSalt.Length + bIn.Length];
                    Buffer.BlockCopy(bSalt, 0, bAll, 0, bSalt.Length);
                    Buffer.BlockCopy(bIn, 0, bAll, bSalt.Length, bIn.Length);
                    bRet = hm.ComputeHash(bAll);
                }
            }

            return Convert.ToBase64String(bRet);
        }
    }
}