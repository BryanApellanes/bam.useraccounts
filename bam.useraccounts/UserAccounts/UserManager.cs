/*
	Copyright © Bryan Apellanes 2015  
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Bam.Net.Configuration;
using Bam.Net.Logging;
using Bam.Net.UserAccounts.Data;
using Bam.Net;
using Bam.Net.Data;
using Bam.Net.ServiceProxy;
using Bam.Net.Messaging;
using Bam.Net.Incubation;
//using Bam.Net.Encryption;
using System.IO;
using System.Net;
using System.Web;
using Bam.UserAccounts;

namespace Bam.Net.UserAccounts
{
    /// <summary>
    /// Class used to manage users of an application
    /// </summary>
    //[Encrypt]
    [Proxy("user", MethodCase = MethodCase.Both)]
    [Serializable]
    public sealed class UserManager : Loggable, IRequiresHttpContext, IUserManager
    {
        static UserManager()
        {
            //UserResolvers.Default.InsertResolver(0, new DaoUserResolver());
        }

        /// <summary>
        /// The name of the account confirmation email template
        /// </summary>
        public const string AccountConfirmationEmailName = "AccountConfirmationEmail";
        /// <summary>
        /// The name of the password reset email template
        /// </summary>
        public const string PasswordResetEmailName = "PasswordResetEmail";

        public UserManager()
        {
            SmtpSettingsProvider = new SmtpSettingsProvider();
            SmtpSettingsVaultPath = Path.Combine(BamHome.DataPath, "SmtpSettings.vault.sqlite");
            PasswordResetTokensExpireInThisManyMinutes = 15;
            LastException = new NullException();
        }

        public UserManager(UserAccountsDatabase db): this()
        {
            Database = db;
        }

        [Exclude]
        public object Clone()
        {
            UserManager result = new UserManager(Database);
            result.CopyProperties(this);
            result.CopyEventHandlers(this);
            result._serviceProvider = _serviceProvider.Clone();
            result.SmtpSettingsProvider = SmtpSettingsProvider;
            return result;
        }

        Incubator _serviceProvider;
        object _serviceProviderLock = new object();

        internal Incubator ServiceProvider
        {
            get
            {
                return _serviceProviderLock.DoubleCheckLock(ref _serviceProvider, () =>
                {
                    Incubator serviceProvider = new Incubator();
                    DaoUserResolver userResolver = new DaoUserResolver();
                    serviceProvider.Set<IUserResolver>(userResolver);
                    serviceProvider.Set<DaoUserResolver>(userResolver);
                    serviceProvider.Set<IDaoUserResolver>(userResolver);
                    DaoRoleResolver roleResolver = new DaoRoleResolver();
                    serviceProvider.Set<IRoleResolver>(roleResolver);
                    serviceProvider.Set<DaoRoleResolver>(roleResolver);
                    serviceProvider.Set<EmailComposer>(new NamedFormatEmailComposer());
                    serviceProvider.Set<IApplicationNameProvider>(DefaultConfigurationApplicationNameProvider.Instance);
                    serviceProvider.Set<UserAccountsDatabase>(UserAccountsDatabase.Default);
                    serviceProvider.Set<IAuthenticator>(new DaoAuthenticator(UserAccountsDatabase.Default));

                    return serviceProvider;
                });
            }
            set => _serviceProvider = value;
        }

        public IAuthenticator Authenticator
        {
            get => ServiceProvider.Get<IAuthenticator>();
            set => ServiceProvider.Set<IAuthenticator>(value);
        }

        public IDaoUserResolver DaoUserResolver
        {
            get => ServiceProvider.Get<IDaoUserResolver>();
            set => ServiceProvider.Set<IDaoUserResolver>(value);
        }

        public IEmailComposer EmailComposer
        {
            get => ServiceProvider.Get<EmailComposer>();
            set => ServiceProvider.Set<EmailComposer>(value);
        }

        public ISmtpSettingsProvider SmtpSettingsProvider
        {
            get;
            set;
        }
        
        [Local]
        public object GetSmtpSettingsVault(string applicationName = null)
        {
            return SmtpSettingsProvider.GetSmtpSettingsVault(applicationName);
        }
        
        public object SmtpSettingsVault => GetSmtpSettingsVault(ApplicationName);

        [Exclude]
        public string SmtpSettingsVaultPath
        {
            get => SmtpSettingsProvider.SmtpSettingsVaultPath;
            set => SmtpSettingsProvider.SmtpSettingsVaultPath = value;
        }

        public int PasswordResetTokensExpireInThisManyMinutes
        {
            get;
            set;
        }

        [Exclude]
        public string ApplicationName => ApplicationNameProvider.GetApplicationName(); // used by loggable implementation

        [Exclude]
        public string LastExceptionMessage => LastException.Message; // used by loggable implementation

        [Exclude]
        public Exception LastException { get; set; }

        public IApplicationNameProvider ApplicationNameProvider
        {
            get => ServiceProvider.Get<IApplicationNameProvider>();
            set => ServiceProvider.Set<IApplicationNameProvider>(value);
        }

        [Local]
        public Email CreateEmail(string fromAddress = null, string fromDisplayName = null)
        {
            return SmtpSettingsProvider.CreateEmail(fromAddress, fromDisplayName);
        }

        internal Email ComposeConfirmationEmail(string subject, object data)
        {
            Email email = EmailComposer.Compose(subject, AccountConfirmationEmailName, data);
            return EmailComposer.SetSmtpHostSettings(SmtpSettingsVault, email);
        }

        internal Email ComposePasswordResetEmail(string subject, object data)
        {
            Email email = EmailComposer.Compose(subject, PasswordResetEmailName, data);
            return EmailComposer.SetSmtpHostSettings(SmtpSettingsVault, email);
        }

        internal void InitializeConfirmationEmail()
        {
            if (!EmailComposer.TemplateExists(AccountConfirmationEmailName))
            {
                string content = @"<!DOCTYPE html PUBLIC ""-//W3C//DTD XHTML 1.0 Transitional//EN"" ""http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"">
<html xmlns = ""http://www.w3.org/1999/xhtml"">  
   <head>
    <meta http - equiv = ""Content-Type"" content = ""text/html; charset=UTF-8"" />       
    <title>{Title}</title>
    <meta name = ""viewport"" content = ""width=device-width, initial-scale=1.0"" />
    </head>
    <body style=""margin: 0; padding: 0;"">
     <table border=""0"" cellpadding=""15"" cellspacing=""0"" width=""100%"">
      <tr>
       <td>
        Hi {UserName},
       </td>
      </tr>
      <tr>
       <td>
        Thanks for signing up for {ApplicationName}.  Please click the link below to confirm your account.
       </td>
      </tr>
      <tr>
       <td>
        <a href=""{ConfirmationUrl}"">{ConfirmationUrl}</a>
       </td>
      </tr>
      <tr>
       <td>
        If you are unable to click on the link, copy and paste the above link into a browser address bar.
       </td>
      </tr>
      <tr>
       <td>
        If you did not sign up for {ApplicationName} you may ignore this email.
       </td>
      </tr>
      <tr>
       <td>
        Thanks,<br>
        The {ApplicationName} team
       </td>
      </tr>
     </table>
    </body>
</html>";
                EmailComposer.SetEmailTemplate(AccountConfirmationEmailName, content, true);
            }
        }

        internal void InitializePasswordResetEmail()
        {
            if (!EmailComposer.TemplateExists(PasswordResetEmailName))
            {
                string content = @"<!DOCTYPE html PUBLIC ""-//W3C//DTD XHTML 1.0 Transitional//EN"" ""http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"">
<html xmlns = ""http://www.w3.org/1999/xhtml"">  
   <head>
    <meta http - equiv = ""Content-Type"" content = ""text/html; charset=UTF-8"" />       
    <title>{Title}</title>
    <meta name = ""viewport"" content = ""width=device-width, initial-scale=1.0"" />
    </head>
    <body style=""margin: 0; padding: 0;"">
     <table border=""0"" cellpadding=""15"" cellspacing=""0"" width=""100%"">
      <tr>
       <td>
        Hi {UserName},
       </td>
      </tr>
      <tr>
       <td>
        Someone recently requested a password reset for {ApplicationName}.  If this was you click the link below to reset your password.
       </td>
      </tr>
      <tr>
       <td>
        <a href=""{PasswordResetUrl}"">{PasswordResetUrl}</a>
       </td>
      </tr>
      <tr>
       <td>
        If you are unable to click on the link, copy and paste the above link into a browser address bar.
       </td>
      </tr>
      <tr>
       <td>
        If you did not request a password reset for {ApplicationName} you can disregard this email.
       </td>
      </tr>
      <tr>
       <td>
        Thanks,<br>
        The {ApplicationName} team
       </td>
      </tr>
     </table>
    </body>
</html>";
                EmailComposer.SetEmailTemplate(PasswordResetEmailName, content, true);
            }
        }

        Func<string, string> _getConfirmationUrlFunction;
        object _getConfirmationUrlFunctionLock = new object();
        public Func<string,string> GetConfirmationUrlFunction
        {
            get
            {
                IHttpContext context = HttpContext;
                string func(string token)
                {
                    string baseAddress = ServiceProxySystem.GetBaseAddress(context.Request);
                    return $"{baseAddress}auth/confirmAccount?token={token}&layout=basic";
                }

                return func;
            }
            set => _getConfirmationUrlFunction = value;
        }

        internal string GetConfirmationUrl(string token)
        {
            return GetConfirmationUrlFunction(token);
        }

        Func<string, string> _getPasswordResetUrlFunction;
        object _getPasswordResetUrlFunctionLock = new object();
        public Func<string, string> GetPasswordResetUrlFunction
        {
            get
            {
                IHttpContext context = HttpContext;
                Func<string, string> func = (token) =>
                {
                    string baseAddress = ServiceProxySystem.GetBaseAddress(context.Request);
                    return $"{baseAddress}auth/resetPassword?token={token}&layout=basic";
                };

                return func;
            }
            set => _getPasswordResetUrlFunction = value;
        }

        internal string GetPasswordResetUrl(string token)
        {
            return GetPasswordResetUrlFunction(token);
        }

        Database _database;
        public Database Database
        {
            get => _database ?? (_database = Db.For<User>());
            set
            {
                _database = value;
                DaoUserResolver.Database = _database;
                Authenticator = new DaoAuthenticator(_database);
                User.UserDatabase = _database;
            }
        }

        /// <summary>
        /// The event that is fired when someone logs in
        /// </summary>
        [Verbosity(VerbosityLevel.Information, SenderMessageFormat = "{ApplicationName}::{UserName}:: ForgotPasswordSucceeded")]
        public event EventHandler ForgotPasswordSucceeded;
        /// <summary>
        /// The event that is fired when a login fails
        /// </summary>
        [Verbosity(VerbosityLevel.Information, SenderMessageFormat = "{ApplicationName}::{UserName}:: ForgotPasswordSucceeded: {LastExceptionMessage}")]
        public event EventHandler ForgotPasswordFailed;
        public IServiceProxyResponse ForgotPassword(string emailAddress)
        {
            try
            {
                User user = User.GetByEmail(emailAddress, Database);
                PasswordReset reset = user.PasswordResetsByUserId.AddChild();
                reset.Token = Guid.NewGuid().ToString();
                reset.DateTime = new Instant();
                reset.ExpiresInMinutes = PasswordResetTokensExpireInThisManyMinutes;
                reset.WasReset = false;				

                user.Save(Database);

                PasswordResetEmailData data = new PasswordResetEmailData
                {
                    Title = "Password Reset",
                    UserName = user.UserName,
                    ApplicationName = ApplicationNameProvider.GetApplicationName(),
                    PasswordResetUrl = GetPasswordResetUrl(reset.Token)
                };
                string subject = "Password Reset for {0}"._Format(data.ApplicationName);
                string email = user.Email;
                ComposePasswordResetEmail(subject, data).To(email).Send();
                FireEvent(ForgotPasswordSucceeded);
                return GetSuccess<ForgotPasswordResponse>(reset.Token, "Password email was sent to {0}"._Format(email));
            }
            catch (Exception ex)
            {
                LastException = ex;
                FireEvent(ForgotPasswordFailed);
                return GetFailure<ForgotPasswordResponse>(ex);
            }
        }

        /// <summary>
        /// The vent that is fired when someone logs in
        /// </summary>
        [Verbosity(VerbosityLevel.Information, SenderMessageFormat = "{ApplicationName}::{UserName}:: LoginSucceeded")]
        public event EventHandler LoginSucceeded;
        /// <summary>
        /// The event that is fired when a login fails
        /// </summary>
        [Verbosity(VerbosityLevel.Information, SenderMessageFormat = "{ApplicationName}::{UserName}:: LoginFailed: {LastExceptionMessage}")]
        public event EventHandler LoginFailed;
        public IServiceProxyResponse Login(string userName, string passHash)
        {
            EventHandler eventToFire = LoginFailed;
            LoginResponse result = GetFailure<LoginResponse>(new Exception("User name and password combination was invalid"));
            try
            {
                bool passwordIsValid = Authenticator.IsPasswordValid(userName, passHash);
                if (passwordIsValid)
                {
                    eventToFire = LoginSucceeded;
                    result = GetSuccess<LoginResponse>(passwordIsValid);
                    User user = null;
                    user = userName.Contains("@") ? User.GetByEmail(userName, Database) : User.GetByUserName(userName, Database);
                    DaoUserResolver.SetUser(HttpContext, user, true, Database);
                    user.AddLoginRecord(Database);
                }              
            }
            catch (Exception ex)
            {
                eventToFire = LoginFailed;
                result = GetFailure<LoginResponse>(ex);
            }

            FireEvent(eventToFire, EventArgs.Empty);
            return result;
        }

        /// <summary>
        /// The event that is fired when someone signs up
        /// </summary>
        [Verbosity(VerbosityLevel.Information, SenderMessageFormat = "{ApplicationName}::{UserName}:: SignUpSucceeded")]
        public event EventHandler SignUpSucceeded;
        /// <summary>
        /// The event that is fired when a sign up fails
        /// </summary>
        [Verbosity(VerbosityLevel.Information, SenderMessageFormat = "{ApplicationName}::{UserName}:: SignUpFailed: {LastExceptionMessage}")]
        public event EventHandler SignUpFailed;
        public IServiceProxyResponse SignUp(string emailAddress, string userName, string passHash, bool sendConfirmationEmail)
        {
            SignUpOptions options = new SignUpOptions { EmailAddress = emailAddress, UserName = userName, PasswordHash = passHash, SendConfirmation = sendConfirmationEmail };
            try
            {
                IApplicationNameProvider appNameResolver = ApplicationNameProvider;
                User user = User.Create(userName, emailAddress, passHash, appNameResolver, true, true, false, Database);
                if (sendConfirmationEmail)
                {
                    RequestConfirmationEmail(emailAddress);
                }
                object jsonSafe = user.ToJsonSafe();
                FireEvent(SignUpSucceeded, new UserManagerEventArgs { UserJson = jsonSafe.ToJson(), SignUpOptions = options });
                return GetSuccess<SignUpResponse>(jsonSafe);
            }
            catch (Exception ex)
            {
                LastException = ex;
                FireEvent(SignUpFailed, new UserManagerEventArgs { SignUpOptions = options });
                return GetFailure<SignUpResponse>(ex);
            }
        }
        /// <summary>
        /// The vent that is fired when someone signs up
        /// </summary>
        [Verbosity(VerbosityLevel.Information, SenderMessageFormat = "{ApplicationName}::{UserName}:: SignOutStarted")]
        public event EventHandler SignOutStarted;
        /// <summary>
        /// The vent that is fired when someone signs up
        /// </summary>
        [Verbosity(VerbosityLevel.Information, SenderMessageFormat = "{ApplicationName}::{UserName}:: SignOutSucceeded")]
        public event EventHandler SignOutSucceeded;
        /// <summary>
        /// The event that is fired when a sign up fails
        /// </summary>
        [Verbosity(VerbosityLevel.Information, SenderMessageFormat = "{ApplicationName}::{UserName}:: SignOutFailed: {LastExceptionMessage}")]
        public event EventHandler SignOutFailed;
        public IServiceProxyResponse SignOut()
        {
            try
            {
                IRequest request = HttpContext.Request;
                
                if (HttpContext.Request.Cookies[Session.CookieName] != null)
                {
                    IResponse response = HttpContext.Response;
                    Cookie cookie = request.Cookies[Session.CookieName];                    
                    cookie.Expires = DateTime.Now.AddDays(-1d);

                    response.Cookies.Add(cookie);
                }
                FireEvent(SignOutStarted);
                Session.End(Database);
                FireEvent(SignOutSucceeded);
                return GetSuccess<SignOutResponse>("Sign out successful");
            }
            catch (Exception ex)
            {
                LastException = ex;
                FireEvent(SignOutFailed);
                return GetFailure<SignOutResponse>(ex);
            }
        }
        
        [Verbosity(VerbosityLevel.Information, SenderMessageFormat = "{ApplicationName}::{UserName}:: RequestConfirmationEmailSucceeded")]
        public event EventHandler RequestConfirmationEmailSucceeded;
        [Verbosity(VerbosityLevel.Information, SenderMessageFormat = "{ApplicationName}::{UserName}:: RequestConfirmationEmailFailed: {LastExceptionMessage}")]
        public event EventHandler RequestConfirmationEmailFailed;

        public IServiceProxyResponse RequestConfirmationEmail(string emailAddress, int accountIndex = 0)
        {
            try
            {
                User user = User.GetByEmail(emailAddress, Database);
                if (user == null)
                {
                    throw new UserNameNotFoundException(emailAddress);
                }

                Account account = null;
                if (user.AccountsByUserId.Count == 0)
                {
                    account = Account.Create(user, ApplicationNameProvider.GetApplicationName(), user.UserName, false, Database);
                }
                else if(user.AccountsByUserId.Count <= accountIndex)
                {
                    account = user.AccountsByUserId[accountIndex];
                }
                else
                {
                    account = user.AccountsByUserId[0];
                }

                AccountConfirmationEmailData data = new AccountConfirmationEmailData
                {
                    Title = "Account Confirmation",
                    UserName = user.UserName,
                    ApplicationName = ApplicationNameProvider.GetApplicationName(),
                    ConfirmationUrl = GetConfirmationUrl(account.Token)
                };

                string subject = "Account Registration Confirmation";
                ComposeConfirmationEmail(subject, data).To(user.Email).Send();

                FireEvent(RequestConfirmationEmailSucceeded);
                return GetSuccess<SendEmailResponse>(true);
            }
            catch (Exception ex)
            {
                LastException = ex;
                FireEvent(RequestConfirmationEmailFailed);
                return GetFailure<SendEmailResponse>(ex);
            }
        }

        [Verbosity(VerbosityLevel.Information, SenderMessageFormat = "{ApplicationName}::{UserName}:: ConfirmAccountSucceeded")]
        public event EventHandler ConfirmAccountSucceeded;
        [Verbosity(VerbosityLevel.Information, SenderMessageFormat = "{ApplicationName}::{UserName}:: ConfirmAccountFailed: {LastExceptionMessage}")]
        public event EventHandler ConfirmAccountFailed;

        public IServiceProxyResponse ConfirmAccount(string token)
        {
            try
            {
                Account account = Account.OneWhere(c => c.Token == token, Database);
                if (account == null)
                {
                    throw new ArgumentException("Invalid token");
                }
                else
                {
                    account.IsConfirmed = true;
                    account.Save(Database);
                }

                FireEvent(ConfirmAccountSucceeded);
                return GetSuccess<ConfirmResponse>(account.Provider);
            }
            catch (Exception ex)
            {
                LastException = ex;
                FireEvent(ConfirmAccountFailed);
                return GetFailure<ConfirmResponse>(ex);
            }
        }

        public IServiceProxyResponse IsUserNameAvailable(string userName)
        {
            try
            {
                bool? isAvailable = !User.Exists(userName, Database);
                return GetSuccess<CheckUserNameResponse>(isAvailable);
            }
            catch (Exception ex)
            {
                return GetFailure<CheckUserNameResponse>(ex);
            }
        }

        public IServiceProxyResponse IsEmailInUse(string emailAddress)
        {
            try
            {
                User user = User.GetByEmail(emailAddress, Database);
                bool? emailIsInUse = user != null;
                return GetSuccess<CheckEmailResponse>(emailIsInUse);
            }
            catch (Exception ex)
            {
                return GetFailure<CheckEmailResponse>(ex);
            }
        }

        private T GetSuccess<T>(object data, string message = null) where T: UserAccountResponse, new()
        {
            T result = new T {Success = true, Message = message, Data = data};
            return result;
        }

        private T GetFailure<T>(Exception ex) where T: UserAccountResponse, new()
        {
            T result = new T()
            {
                Success = false,
                Message = ex.Message,
                Data = null
            };
            return result;
        }

        public PasswordResetPageResponse PasswordResetPage(string token, string layout)
        {
            PasswordResetPageResponse response = GetSuccess<PasswordResetPageResponse>(token);
            response.Token = token;
            response.Layout = layout;
            return response;
        }

        [Verbosity(VerbosityLevel.Information, SenderMessageFormat = "{ApplicationName}::{UserName}:: RequestConfirmationEmailSucceeded")]
        public event EventHandler ResetPasswordSucceeded;
        [Verbosity(VerbosityLevel.Information, SenderMessageFormat = "{ApplicationName}::{UserName}:: RequestConfirmationEmailFailed: {LastExceptionMessage}")]
        public event EventHandler ResetPasswordFailed;

        public IServiceProxyResponse ResetPassword(string passHash, string resetToken)
        {
            try
            {
                PasswordReset reset = PasswordReset.OneWhere(c => c.Token == resetToken, Database);
                if (reset == null)
                {
                    throw new InvalidTokenException();
                }

                Instant timeOfRequest = new Instant(reset.DateTime.Value);
                Instant now = new Instant();
                if (now.DiffInMinutes(timeOfRequest) > reset.ExpiresInMinutes.Value)
                {
                    throw new InvalidTokenException();
                }

                Password.Set(reset.UserOfUserId, passHash, Database);
                FireEvent(ResetPasswordSucceeded);
                return GetSuccess<PasswordResetResponse>(true, "Password was successfully reset");
            }
            catch (Exception ex)
            {
                LastException = ex;
                FireEvent(ResetPasswordFailed);
                return GetFailure<PasswordResetResponse>(ex);
            }
        }
/*
        public dynamic GetCurrent()
        {
            bool isAuthenticated = false;
            IUser user = GetUser(HttpContext);

            if (user.Id.Value != User.Anonymous.Id.Value)
            {
                isAuthenticated = true;
            }

            int loginCount = isAuthenticated ? user.LoginsByUserId.Count : 0;

            dynamic result = new
            {
                userName = user.UserName,
                id = user.Id,
                isAuthenticated = isAuthenticated,
                loginCount = loginCount
            };

            return result;
        }*/

        [Exclude]
        public string UserName => GetUser(HttpContext).UserName;

        [Exclude]
        public IUser GetUser(IHttpContext context)
        {
            context = context ?? HttpContext;
            if(context == null)
            {
                return User.Anonymous;
            }
            return Session.Get(context).UserOfUserId ?? User.Anonymous;
        }

        [Exclude]
        public Session Session => Session.Get(HttpContext);

        public IHttpContext HttpContext
        {
            get;
            set;
        }
    }
}
