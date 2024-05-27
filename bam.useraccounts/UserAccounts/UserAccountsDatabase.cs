using Bam.Configuration;
using Bam.Data;
using Bam.Data.SQLite;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.UserAccounts
{
    public class UserAccountsDatabase
    {
/*        public static implicit operator Database(UserAccountsDatabase db)
        {
            return db.Database;
        }*/

        public static implicit operator UserAccountsDatabase(Database db)
        {
            return new UserAccountsDatabase(db);
        }

        public UserAccountsDatabase(IDatabase db)
        {
            Database = db;
        }

        public IDatabase Database { get; }

        /*        static UserAccountsDatabase _default;
                static object _defaultLock = new object();           
                public static UserAccountsDatabase Default
                {
                    get
                    {
                        return _defaultLock.DoubleCheckLock(ref _default, 
                            () => 
                            {
                                UserAccountsDatabase db = new UserAccountsDatabase(new SQLiteDatabase(BamHome.DataPath, DefaultConfigurationApplicationNameProvider.Instance.GetApplicationName()));
                                db.Database.TryEnsureSchema<UserAccounts.Data.User>();
                                return db;
                            });
                    }
                }*/
    }
}
