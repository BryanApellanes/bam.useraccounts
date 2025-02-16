namespace Bam.Encryption
{
    public interface INamedCredentialProvider
    {
        string GetUserNameFor(string targetIdentifier);
        string GetPasswordFor(string targetIdentifier);
    }
}
