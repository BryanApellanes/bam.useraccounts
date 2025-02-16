namespace Bam.Encryption
{
    public interface IServiceCredentialProvider
    {
        string GetUserNameFor(string machineName, string serviceName);
        string GetPasswordFor(string machineName, string serviceName);
    }
}
