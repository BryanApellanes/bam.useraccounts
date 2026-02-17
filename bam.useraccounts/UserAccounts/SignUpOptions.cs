namespace Bam.UserAccounts
{
    public class SignUpOptions
    {
        public string EmailAddress { get; set; } = null!;
        public string UserName { get; set; } = null!;
        public string PasswordHash { get; set; } = null!;
        public bool SendConfirmation { get; set; }
    }
}
