using Bam.Net;
using Bam.Net.ServiceProxy;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Bam.UserAccounts
{
    public abstract class UserAccountResponse : IServiceProxyResponse
    {
        public object Data
        {
            get;
            set;
        }

        public string Message
        {
            get;
            set;
        }

        public bool Success
        {
            get;
            set;
        }

        public T? DataTo<T>()
        {
            string json = JsonConvert.SerializeObject(Data);
            return JsonConvert.DeserializeObject<T>(json);
        }
    }
}
