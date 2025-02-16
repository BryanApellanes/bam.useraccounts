/*
	Copyright © Bryan Apellanes 2015  
*/

namespace Bam.UserAccounts
{
    public class PasswordResetPageResponse: UserAccountResponse
    {
        public PasswordResetPageResponse() { }

        public string Token { get; set; }
        public string Layout { get; set; }
    }
}
