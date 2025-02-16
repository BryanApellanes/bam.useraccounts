/*
	Copyright © Bryan Apellanes 2015  
*/

namespace Bam.UserAccounts
{
    public class AccountCreationFailedException: Exception
    {
        public AccountCreationFailedException(string userName)
            : base("The account was not found for ({0})".Format(userName))
        {

        }
    }
}
