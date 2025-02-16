/*
	Copyright © Bryan Apellanes 2015  
*/

namespace Bam.ServiceProxy
{
    public interface IRoleResolver: IRequiresHttpContext
    {
        bool IsInRole(IUserResolver userResolver, string roleName);        
        string[] GetRoles(IUserResolver userResolver);
    }
}
