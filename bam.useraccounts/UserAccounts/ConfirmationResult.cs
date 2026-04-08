using Org.BouncyCastle.X509;

namespace Bam.UserAccounts;

public class ConfirmationResult : UserAccountResponse
{
    public bool Confirmed { get; set; }
    public X509Certificate? Certificate { get; set; }
}
