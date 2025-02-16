/*
	Copyright © Bryan Apellanes 2015  
*/

namespace Bam
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class RoleRequiredAttribute: Attribute
    {
        public RoleRequiredAttribute(string redirectTo, params string[] roles)
        {
            this.Roles = roles;
            this.RedirectTo = redirectTo;
        }

        public string[] Roles { get; set; }
        public string RedirectTo { get; set; }
    }
}
