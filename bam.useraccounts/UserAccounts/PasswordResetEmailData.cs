/*
	Copyright © Bryan Apellanes 2015  
*/

namespace Bam.UserAccounts
{
    public class PasswordResetEmailData
    {
        public string Title { get; set; } = null!;
        public string UserName { get; set; } = null!;
        public string ApplicationName { get; set; } = null!;
        public string PasswordResetUrl { get; set; } = null!;
    }
}
