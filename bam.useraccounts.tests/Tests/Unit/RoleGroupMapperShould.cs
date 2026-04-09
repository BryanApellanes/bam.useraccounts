using Bam.DependencyInjection;
using Bam.Protocol;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Profile;
using Bam.Test;
using Bam.UserAccounts;
using NSubstitute;

namespace Bam.UserAccounts.Tests.Unit;

[UnitTestMenu("RoleGroupMapper Should", Selector = "rgm")]
public class RoleGroupMapperShould : UnitTestMenuContainer
{
    public RoleGroupMapperShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    private static IProfileRepository CreateMockRepository()
    {
        var repo = Substitute.For<IProfileRepository>();
        repo.SaveGroup(Arg.Any<GroupData>()).Returns(callInfo =>
        {
            var g = callInfo.Arg<GroupData>();
            return g;
        });
        return repo;
    }

    private static RoleGroupMapper CreateMapperWithMappings(IProfileRepository repo)
    {
        var mapper = new RoleGroupMapper(repo);
        mapper.MapRole("admin", "Administrators", BamAccess.Write);
        mapper.MapRole("editor", "Editors", BamAccess.Execute);
        mapper.MapRole("viewer", "Viewers", BamAccess.Read);
        return mapper;
    }

    [UnitTest]
    public void MapRoleToAccessLevel()
    {
        var repo = CreateMockRepository();
        When.A<RoleGroupMapper>("maps role to access level",
            () => CreateMapperWithMappings(repo),
            (mapper) => mapper.GetAccessForRole("admin"))
        .TheTest
        .ShouldPass(because =>
        {
            because.TheObjectUnderTest
                .IsNotNull()
                .IsObjectOfType<RoleGroupMapper>();

            because.TheResult
                .IsNotNull()
                .IsEqualTo(BamAccess.Write);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ReturnCorrectAccessForEditorRole()
    {
        var repo = CreateMockRepository();
        When.A<RoleGroupMapper>("gets access level for editor role",
            () => CreateMapperWithMappings(repo),
            (mapper) => mapper.GetAccessForRole("editor"))
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .IsEqualTo(BamAccess.Execute);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void GetGroupForMappedRole()
    {
        var repo = CreateMockRepository();
        var existingGroup = new GroupData { Name = "Administrators", Description = "Admin group" };
        repo.FindGroupByName("Administrators").Returns(existingGroup);

        When.A<RoleGroupMapper>("gets group for mapped role",
            () => CreateMapperWithMappings(repo),
            (mapper) => mapper.GetGroupForRole("admin"))
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<GroupData>("has correct name", g => g!.Name == "Administrators");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void CreateGroupIfNotExists()
    {
        var repo = CreateMockRepository();
        repo.FindGroupByName("Administrators").Returns((GroupData)null!);

        When.A<RoleGroupMapper>("gets group for role with no existing group",
            () => CreateMapperWithMappings(repo),
            (mapper) => mapper.GetGroupForRole("admin"))
        .TheTest
        .ShouldPass(because =>
        {
            repo.Received(1).SaveGroup(Arg.Is<GroupData>(g => g.Name == "Administrators"));

            because.TheResult
                .IsNotNull()
                .As<GroupData>("has correct name", g => g!.Name == "Administrators");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void AssignRolesToPersonViaRepository()
    {
        var repo = CreateMockRepository();
        var adminGroup = new GroupData { Name = "Administrators" };
        var editorGroup = new GroupData { Name = "Editors" };
        repo.FindGroupByName("Administrators").Returns(adminGroup);
        repo.FindGroupByName("Editors").Returns(editorGroup);

        When.A<RoleGroupMapper>("assigns roles to person",
            () => CreateMapperWithMappings(repo),
            (mapper) =>
            {
                mapper.AssignRolesToPerson("person-abc", "admin", "editor");
                return true;
            })
        .TheTest
        .ShouldPass(because =>
        {
            repo.Received(1).AddPersonToGroup("person-abc", "Administrators");
            repo.Received(1).AddPersonToGroup("person-abc", "Editors");

            because.ItsTrue("completed without error", true);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RemoveRolesFromPersonViaRepository()
    {
        var repo = CreateMockRepository();

        When.A<RoleGroupMapper>("removes roles from person",
            () => CreateMapperWithMappings(repo),
            (mapper) =>
            {
                mapper.RemoveRolesFromPerson("person-abc", "admin");
                return true;
            })
        .TheTest
        .ShouldPass(because =>
        {
            repo.Received(1).RemovePersonFromGroup("person-abc", "Administrators");

            because.ItsTrue("completed without error", true);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void GetRolesForPersonByGroupMembership()
    {
        var repo = CreateMockRepository();
        repo.GetGroupsForPerson("person-abc").Returns(new List<GroupData>
        {
            new() { Name = "Administrators" },
            new() { Name = "Editors" }
        });

        When.A<RoleGroupMapper>("gets roles for a person",
            () => CreateMapperWithMappings(repo),
            (mapper) => mapper.GetRolesForPerson("person-abc"))
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<string[]>("contains admin", roles => roles!.Contains("admin"))
                .As<string[]>("contains editor", roles => roles!.Contains("editor"))
                .As<string[]>("does not contain viewer", roles => !roles!.Contains("viewer"))
                .As<string[]>("has exactly 2 roles", roles => roles!.Length == 2);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ReturnEmptyRolesForPersonWithNoGroups()
    {
        var repo = CreateMockRepository();
        repo.GetGroupsForPerson("person-none").Returns(new List<GroupData>());

        When.A<RoleGroupMapper>("gets roles for person with no groups",
            () => CreateMapperWithMappings(repo),
            (mapper) => mapper.GetRolesForPerson("person-none"))
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<string[]>("is empty", roles => roles!.Length == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void IgnoreUnmappedRoleOnRemoval()
    {
        var repo = CreateMockRepository();

        When.A<RoleGroupMapper>("removes an unmapped role",
            () => CreateMapperWithMappings(repo),
            (mapper) =>
            {
                mapper.RemoveRolesFromPerson("person-abc", "nonexistent-role");
                return true;
            })
        .TheTest
        .ShouldPass(because =>
        {
            repo.DidNotReceive().RemovePersonFromGroup(Arg.Any<string>(), Arg.Any<string>());
            because.ItsTrue("completed without error", true);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}
