using Bam.UserAccounts.Data;

namespace Bam.UserAccounts
{
    public abstract class Authenticator: IAuthenticator
    {
        public abstract bool IsPasswordHashValid(IUser user, string passwordHash);

        public virtual bool IsPasswordHashValid(string userName, string passwordHash)
        {
            return IsPasswordHashValid(GetUser(userName), passwordHash);
        }

        public virtual bool IsPasswordValid(IUser user, string password)
        {
            return IsPasswordHashValid(user, password.Sha1());
        }

        public virtual bool IsPasswordValid(string userName, string password)
        {
            return IsPasswordHashValid(GetUser(userName), password.Sha1());
        }

        protected abstract IUser GetUser(string userName);
    }
}
