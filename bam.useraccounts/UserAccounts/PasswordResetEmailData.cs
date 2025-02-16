/*
	Copyright © Bryan Apellanes 2015  
*/

namespace Bam.UserAccounts
{
    public class PasswordResetEmailData
    {
        public string Title { get; set; }
        public string UserName { get; set; }
        public string ApplicationName { get; set; }
        public string PasswordResetUrl { get; set; }
    }
}
