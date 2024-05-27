/*
	Copyright © Bryan Apellanes 2015  
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.ServiceProxy
{
    public interface IRoleResolver: IRequiresHttpContext
    {
        bool IsInRole(IUserResolver userResolver, string roleName);        
        string[] GetRoles(IUserResolver userResolver);
    }
}
