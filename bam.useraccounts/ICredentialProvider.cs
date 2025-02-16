namespace Bam.Encryption
{
    public interface ICredentialProvider
    {
        string GetUserName();
        string GetPassword();
    }
}
