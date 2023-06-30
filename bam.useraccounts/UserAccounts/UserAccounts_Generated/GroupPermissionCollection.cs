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
    public class GroupPermissionCollection: DaoCollection<GroupPermissionColumns, GroupPermission>
    { 
		public GroupPermissionCollection(){}
		public GroupPermissionCollection(IDatabase db, DataTable table, Bam.Net.Data.IDao dao = null, string rc = null) : base(db, table, dao, rc) { }
		public GroupPermissionCollection(DataTable table, Bam.Net.Data.Dao dao = null, string rc = null) : base(table, dao, rc) { }
		public GroupPermissionCollection(IQuery<GroupPermissionColumns, GroupPermission> q, Bam.Net.Data.IDao dao = null, string rc = null) : base(q, dao, rc) { }
		public GroupPermissionCollection(IDatabase db, IQuery<GroupPermissionColumns, GroupPermission> q, bool load) : base(db, q, load) { }
		public GroupPermissionCollection(IQuery<GroupPermissionColumns, GroupPermission> q, bool load) : base(q, load) { }
    }
}