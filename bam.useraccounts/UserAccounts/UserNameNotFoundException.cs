/*
	Copyright © Bryan Apellanes 2015  
*/

namespace Bam.UserAccounts
{
    public class UserNameNotFoundException: Exception
    {
        public UserNameNotFoundException(string userName)
            : base("The specified user ({0}) was not found".Format(userName))
        { }    
    }
}
