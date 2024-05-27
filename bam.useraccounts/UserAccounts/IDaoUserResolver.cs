using Bam.Data;
using Bam.ServiceProxy;
using Bam.UserAccounts.Data;

namespace Bam.UserAccounts
{
    public interface IDaoUserResolver: IUserResolver, IUserProvider
    {
        IDatabase Database { get; set; }
        
        void SetUser(IHttpContext context, IUser user, bool isAuthenticated, Database db = null);
    }
}