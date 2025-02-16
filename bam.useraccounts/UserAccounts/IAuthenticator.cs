namespace Bam.UserAccounts
{
    public interface IAuthenticator
    {
        bool IsPasswordValid(string userName, string password);

        // TODO: redesign this concept to align with modern authentication concepts
        // something like the following.
        //
        // IChallenge Authenticate(string userName);
        // IAuthentication Challenge(string userName, ulong authenticatorId);
    }
}

