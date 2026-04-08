using Bam.Protocol;
using Bam.Protocol.Data.Profile;

namespace Bam.UserAccounts;

public interface IRoleGroupMapper
{
    void MapRole(string roleName, string groupName, BamAccess accessLevel);
    GroupData GetGroupForRole(string roleName);
    BamAccess GetAccessForRole(string roleName);
    string[] GetRolesForPerson(string personHandle);
    void AssignRolesToPerson(string personHandle, params string[] roleNames);
    void RemoveRolesFromPerson(string personHandle, params string[] roleNames);
}
