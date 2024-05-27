/*
	Copyright © Bryan Apellanes 2015  
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.UserAccounts
{
    public class UserNameNotFoundException: Exception
    {
        public UserNameNotFoundException(string userName)
            : base("The specified user ({0}) was not found".Format(userName))
        { }    
    }
}
