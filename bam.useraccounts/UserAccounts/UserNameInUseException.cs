/*
	Copyright © Bryan Apellanes 2015  
*/

namespace Bam.UserAccounts
{
    public class UserNameInUseException: Exception
    {
        public UserNameInUseException()
        {
        }

        public UserNameInUseException(string userName)
            : base("The specified userName ({0}) is already in use".Format(userName))
        {
        }
    }
}
