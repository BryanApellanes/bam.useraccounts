/*
	Copyright © Bryan Apellanes 2015  
*/

namespace Bam.UserAccounts
{
    public class PasswordResetPageResponse: UserAccountResponse
    {
        public PasswordResetPageResponse() { }

        public string Token { get; set; } = null!;
        public string Layout { get; set; } = null!;
    }
}
