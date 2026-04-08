using Bam.Protocol;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Profile;

namespace Bam.UserAccounts;

public class RoleGroupMapper : IRoleGroupMapper
{
    private readonly IProfileRepository _profileRepository;
    private readonly Dictionary<string, RoleMapping> _roleMappings = new();

    public RoleGroupMapper(IProfileRepository profileRepository)
    {
        _profileRepository = profileRepository;
    }

    public void MapRole(string roleName, string groupName, BamAccess accessLevel)
    {
        _roleMappings[roleName] = new RoleMapping(groupName, accessLevel);
    }

    public GroupData GetGroupForRole(string roleName)
    {
        if (!_roleMappings.TryGetValue(roleName, out var mapping))
        {
            throw new InvalidOperationException($"No group mapping for role '{roleName}'");
        }

        var group = _profileRepository.FindGroupByName(mapping.GroupName);
        if (group == null)
        {
            group = _profileRepository.SaveGroup(new GroupData
            {
                Name = mapping.GroupName,
                Description = $"Group for role '{roleName}'"
            });
        }

        return group;
    }

    public BamAccess GetAccessForRole(string roleName)
    {
        if (!_roleMappings.TryGetValue(roleName, out var mapping))
        {
            throw new InvalidOperationException($"No group mapping for role '{roleName}'");
        }

        return mapping.AccessLevel;
    }

    public string[] GetRolesForPerson(string personHandle)
    {
        var groups = _profileRepository.GetGroupsForPerson(personHandle);
        var groupNames = groups.Select(g => g.Name).ToHashSet();

        return _roleMappings
            .Where(kvp => groupNames.Contains(kvp.Value.GroupName))
            .Select(kvp => kvp.Key)
            .ToArray();
    }

    public void AssignRolesToPerson(string personHandle, params string[] roleNames)
    {
        foreach (var roleName in roleNames)
        {
            var group = GetGroupForRole(roleName);
            _profileRepository.AddPersonToGroup(personHandle, group.Name);
        }
    }

    public void RemoveRolesFromPerson(string personHandle, params string[] roleNames)
    {
        foreach (var roleName in roleNames)
        {
            if (!_roleMappings.TryGetValue(roleName, out var mapping)) continue;
            _profileRepository.RemovePersonFromGroup(personHandle, mapping.GroupName);
        }
    }

    private record RoleMapping(string GroupName, BamAccess AccessLevel);
}
