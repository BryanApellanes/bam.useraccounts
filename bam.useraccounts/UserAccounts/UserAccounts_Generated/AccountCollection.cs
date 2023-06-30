/*
	Copyright © Bryan Apellanes 2015  
*/
using System;
using System.Collections.Generic;
using System.Text;
using System.Data;
using System.Data.Common;
using Bam.Net.Data;

namespace Bam.Net.UserAccounts.Data
{
    public class AccountCollection: DaoCollection<AccountColumns, Account>
    { 
		public AccountCollection(){}
		public AccountCollection(IDatabase db, DataTable table, Bam.Net.Data.Dao dao = null, string rc = null) : base(db, table, dao, rc) { }
		public AccountCollection(DataTable table, Bam.Net.Data.Dao dao = null, string rc = null) : base(table, dao, rc) { }
		public AccountCollection(IQuery<AccountColumns, Account> q, Bam.Net.Data.Dao dao = null, string rc = null) : base(q, dao, rc) { }
		public AccountCollection(IDatabase db, IQuery<AccountColumns, Account> q, bool load) : base(db, q, load) { }
		public AccountCollection(IQuery<AccountColumns, Account> q, bool load) : base(q, load) { }
    }
}