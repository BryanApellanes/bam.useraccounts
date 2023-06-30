using Bam.Net.UserAccounts.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Net.UserAccounts
{
    public interface IAuthenticator
    {
        bool IsPasswordValid(string userName, string password);

        // TODO: redesign this concept to align with modern authentication concepts
        // something like the following.
        //
        // IChallenge Authenticate(string userName);
        // IAuthentication Challenge(string userName, ulong authenticatorId);
    }
}

