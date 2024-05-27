/*
	Copyright © Bryan Apellanes 2015  
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Bam.ServiceProxy;

namespace Bam.UserAccounts
{
    public class PasswordResetPageResponse: UserAccountResponse
    {
        public PasswordResetPageResponse() { }

        public string Token { get; set; }
        public string Layout { get; set; }
    }
}
