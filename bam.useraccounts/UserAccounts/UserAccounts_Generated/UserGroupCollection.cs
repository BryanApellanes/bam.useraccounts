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
    public class UserGroupCollection: DaoCollection<UserGroupColumns, UserGroup>
    { 
		public UserGroupCollection(){}
		public UserGroupCollection(IDatabase db, DataTable table, Bam.Net.Data.IDao dao = null, string rc = null) : base(db, table, dao, rc) { }
		public UserGroupCollection(DataTable table, Bam.Net.Data.IDao dao = null, string rc = null) : base(table, dao, rc) { }
		public UserGroupCollection(IQuery<UserGroupColumns, UserGroup> q, Bam.Net.Data.IDao dao = null, string rc = null) : base(q, dao, rc) { }
		public UserGroupCollection(IDatabase db, IQuery<UserGroupColumns, UserGroup> q, bool load) : base(db, q, load) { }
		public UserGroupCollection(IQuery<UserGroupColumns, UserGroup> q, bool load) : base(q, load) { }
    }
}