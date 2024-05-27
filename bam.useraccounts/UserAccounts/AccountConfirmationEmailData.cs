/*
	Copyright © Bryan Apellanes 2015  
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Bam.UserAccounts.Data;
using Bam.ServiceProxy;

namespace Bam.UserAccounts
{
    public class AccountConfirmationEmailData
    {
        public string Title { get; set; }
        public string UserName { get; set; }
        public string ApplicationName { get; set; }
        public string ConfirmationUrl { get; set; }

    }
}
