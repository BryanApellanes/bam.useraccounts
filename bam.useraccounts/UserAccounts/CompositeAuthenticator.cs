using Bam.Logging;

namespace Bam.UserAccounts
{
    public class CompositeAuthenticator : Loggable, IAuthenticator
    {
        public CompositeAuthenticator()
        {
            _authenticators = new List<IAuthenticator>();
        }

        List<IAuthenticator> _authenticators;
        public IEnumerable<IAuthenticator> Authenticators
        {
            get
            {
                return _authenticators.Select(a => a);
            }
        }

        public void AddAuthenticator(IAuthenticator authenticator)
        {
            _authenticators.Add(authenticator);
        }

        public void AddAuthenticators(params IAuthenticator[] authenticators)
        {
            _authenticators.AddRange(authenticators);
        }

        public bool IsPasswordValid(string userName, string password)
        {
            bool result = false;
            foreach(IAuthenticator authenticator in Authenticators)
            {
                if (result)
                {
                    break;
                }
                result = authenticator.IsPasswordValid(userName, password);
            }

            return result;            
        }
    }
}
