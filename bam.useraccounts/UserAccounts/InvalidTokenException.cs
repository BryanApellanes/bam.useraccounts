/*
	Copyright © Bryan Apellanes 2015  
*/

namespace Bam.UserAccounts
{
    public class InvalidTokenException: Exception
    {
        public InvalidTokenException()
            : base("The specified token was expired or invalid")
        { }
    }
}
