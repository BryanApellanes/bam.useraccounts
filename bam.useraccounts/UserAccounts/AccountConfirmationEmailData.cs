/*
	Copyright © Bryan Apellanes 2015  
*/

namespace Bam.UserAccounts
{
    public class AccountConfirmationEmailData
    {
        public string Title { get; set; } = null!;
        public string UserName { get; set; } = null!;
        public string ApplicationName { get; set; } = null!;
        public string ConfirmationUrl { get; set; } = null!;

    }
}
