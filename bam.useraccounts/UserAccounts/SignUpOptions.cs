namespace Bam.UserAccounts
{
    public class SignUpOptions
    {
        public string EmailAddress { get; set; }
        public string UserName { get; set; }
        public string PasswordHash { get; set; }
        public bool SendConfirmation { get; set; }
    }
}
