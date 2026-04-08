using Bam.Protocol.Data;
using Bam.Protocol.Data.Server;

namespace Bam.UserAccounts;

public class RegistrationResult : UserAccountResponse
{
    public AccountData? AccountData { get; set; }
    public IProfile? Profile { get; set; }
}
