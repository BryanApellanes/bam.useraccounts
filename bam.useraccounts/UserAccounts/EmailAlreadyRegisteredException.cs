/*
	Copyright © Bryan Apellanes 2015  
*/

namespace Bam.UserAccounts
{
    public class EmailAlreadyRegisteredException : Exception
    {
        public EmailAlreadyRegisteredException(string email)
            : base("The specified email ({0}) has already been registered".Format(email))
        {
        }
    }
}
