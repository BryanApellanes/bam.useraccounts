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
    public class UserNameInUseException: Exception
    {
        public UserNameInUseException()
        {
        }

        public UserNameInUseException(string userName)
            : base("The specified userName ({0}) is already in use".Format(userName))
        {
        }
    }
}
