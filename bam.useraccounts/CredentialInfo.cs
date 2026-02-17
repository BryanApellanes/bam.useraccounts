using Newtonsoft.Json;

namespace Bam.Encryption
{
    public class CredentialInfo
    {
        public CredentialInfo()
        {
        }

        [JsonIgnore]
        public bool IsNull
        {
            get
            {
                return string.IsNullOrEmpty(Password);
            }
        }

        public string UserName { get; set; } = null!;
        public string Password { get; set; } = null!;

        /// <summary>
        /// Gets or sets the target service.  This will
        /// be either the name of an application that the
        /// credentials are used to access or the name
        /// of the service that uses the credentials.
        /// May be null.
        /// </summary>
        /// <value>
        /// The target service.
        /// </value>
        public string TargetService { get; set; } = null!;

        /// <summary>
        /// Gets or sets the name of the machine these credentials
        /// are intended for.  May be null.
        /// </summary>
        /// <value>
        /// The name of the machine.
        /// </value>
        public string MachineName { get; set; } = null!;
    }
}
