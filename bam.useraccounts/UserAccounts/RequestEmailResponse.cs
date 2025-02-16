/*
	Copyright © Bryan Apellanes 2015  
*/

namespace Bam.UserAccounts
{
    public abstract class RequestEmailResponse : UserAccountResponse
    {
        public bool EmailSent { get; set; }
    }
}
