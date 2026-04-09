using Bam.DependencyInjection;
using Bam.Protocol;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Common;
using Bam.Protocol.Data.Profile;
using Bam.Protocol.Data.Server;
using Bam.Protocol.Profile;
using Bam.Protocol.Profile.Registration;
using Bam.Test;
using Bam.UserAccounts;
using NSubstitute;

namespace Bam.UserAccounts.Tests.Unit;

[UnitTestMenu("UserAccountService Should", Selector = "uas")]
public class UserAccountServiceShould : UnitTestMenuContainer
{
    public UserAccountServiceShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    private static void SetupDefaults(TestCaseRegistry reg)
    {
        var accountManager = Substitute.For<IAccountManager>();
        var profileManager = Substitute.For<IProfileManager>();
        var profileRepository = Substitute.For<IProfileRepository>();
        var validator = new DefaultRegistrationValidator();
        var notifier = Substitute.For<IRegistrationNotifier>();
        var confirmation = Substitute.For<IAccountConfirmation>();
        var roleGroupMapper = Substitute.For<IRoleGroupMapper>();

        var mockProfile = Substitute.For<IProfile>();
        mockProfile.ProfileHandle.Returns("profile-123");
        mockProfile.PersonHandle.Returns("person-abc");
        mockProfile.Name.Returns("Jane Doe");
        mockProfile.DeviceHandle.Returns("device-xyz");

        accountManager.RegisterAccount(Arg.Any<PersonRegistrationData>())
            .Returns(callInfo => new AccountData { PersonHandle = "person-abc" });

        profileManager.FindProfileByHandle(Arg.Any<string>())
            .Returns(mockProfile);

        reg.For<IAccountManager>().Use(accountManager);
        reg.For<IProfileManager>().Use(profileManager);
        reg.For<IProfileRepository>().Use(profileRepository);
        reg.For<IRegistrationValidator>().Use(validator);
        reg.For<IRegistrationNotifier>().Use(notifier);
        reg.For<IAccountConfirmation>().Use(confirmation);
        reg.For<IRoleGroupMapper>().Use(roleGroupMapper);

        reg.For<IUserAccountService>().Use(new UserAccountService(
            accountManager, profileManager, profileRepository,
            validator, notifier, confirmation, roleGroupMapper));
    }

    [UnitTest]
    public void RegisterPersonWithValidData()
    {
        After.Setup(SetupDefaults)
        .When<IUserAccountService>("registers a person with valid data", (svc) =>
        {
            return svc.RegisterPerson(new PersonRegistrationData
            {
                FirstName = "Jane",
                LastName = "Doe",
                Email = "jane@example.com",
                Phone = "555-1234",
                Handle = "janedoe"
            });
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheObjectUnderTest
                .IsNotNull()
                .IsObjectOfType<UserAccountService>();

            because.TheResult
                .IsNotNull()
                .As<RegistrationResult>("succeeds", r => r!.Success)
                .As<RegistrationResult>("has AccountData", r => r!.AccountData != null)
                .As<RegistrationResult>("has correct PersonHandle", r => r!.AccountData!.PersonHandle == "person-abc")
                .As<RegistrationResult>("has Profile", r => r!.Profile != null);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectRegistrationWithMissingFirstName()
    {
        After.Setup(SetupDefaults)
        .When<IUserAccountService>("registers a person without a first name", (svc) =>
        {
            return svc.RegisterPerson(new PersonRegistrationData
            {
                FirstName = "",
                LastName = "Doe"
            });
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<RegistrationResult>("fails", r => !r!.Success)
                .As<RegistrationResult>("has error message about FirstName", r => r!.Message.Contains("FirstName"));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectRegistrationWithMissingLastName()
    {
        After.Setup(SetupDefaults)
        .When<IUserAccountService>("registers a person without a last name", (svc) =>
        {
            return svc.RegisterPerson(new PersonRegistrationData
            {
                FirstName = "Jane",
                LastName = ""
            });
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<RegistrationResult>("fails", r => !r!.Success)
                .As<RegistrationResult>("has error message about LastName", r => r!.Message.Contains("LastName"));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void NotifyAfterSuccessfulPersonRegistration()
    {
        After.Setup(SetupDefaults)
        .When<IUserAccountService>("registers a person and notifies", (svc) =>
        {
            return svc.RegisterPerson(new PersonRegistrationData
            {
                FirstName = "Jane",
                LastName = "Doe"
            });
        })
        .TheTest
        .ShouldPass(because =>
        {
            var notifier = because.TestCaseRegistry.Get<IRegistrationNotifier>();
            notifier.Received(1).OnPersonRegistered(
                Arg.Any<IProfile>(),
                Arg.Any<AccountData>());

            because.TheResult
                .As<RegistrationResult>("succeeds", r => r!.Success);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void NotNotifyAfterFailedRegistration()
    {
        After.Setup(SetupDefaults)
        .When<IUserAccountService>("registers a person with invalid data", (svc) =>
        {
            return svc.RegisterPerson(new PersonRegistrationData
            {
                FirstName = "",
                LastName = ""
            });
        })
        .TheTest
        .ShouldPass(because =>
        {
            var notifier = because.TestCaseRegistry.Get<IRegistrationNotifier>();
            notifier.DidNotReceive().OnPersonRegistered(
                Arg.Any<IProfile>(),
                Arg.Any<AccountData>());

            because.TheResult
                .As<RegistrationResult>("fails", r => !r!.Success);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RegisterDeviceWithValidData()
    {
        After.Setup(reg =>
        {
            SetupDefaults(reg);

            var profileManager = reg.Get<IProfileManager>();
            var mockProfile = Substitute.For<IProfile>();
            mockProfile.Name.Returns("Jane Doe");

            profileManager.RegisterDeviceProfile(Arg.Any<DeviceRegistrationData>(), Arg.Any<string>())
                .Returns(mockProfile);
            profileManager.FindDeviceByHandle(Arg.Any<string>())
                .Returns(new DeviceData { Handle = "device-001", Name = "My Laptop" });
        })
        .When<IUserAccountService>("registers a device for a person", (svc) =>
        {
            return svc.RegisterDevice(new DeviceRegistrationData
            {
                Name = "My Laptop",
                Handle = "device-001"
            }, "person-abc");
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<RegistrationResult>("succeeds", r => r!.Success)
                .As<RegistrationResult>("has Profile", r => r!.Profile != null);

            var notifier = because.TestCaseRegistry.Get<IRegistrationNotifier>();
            notifier.Received(1).OnDeviceRegistered(
                Arg.Any<IProfile>(),
                Arg.Any<DeviceData>());
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectDeviceRegistrationWithMissingName()
    {
        After.Setup(SetupDefaults)
        .When<IUserAccountService>("registers a device without a name", (svc) =>
        {
            return svc.RegisterDevice(new DeviceRegistrationData
            {
                Name = "",
                Handle = "device-001"
            }, "person-abc");
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<RegistrationResult>("fails", r => !r!.Success)
                .As<RegistrationResult>("has error message about device name", r => r!.Message.Contains("Device name"));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RegisterOrganizationWithValidData()
    {
        After.Setup(reg =>
        {
            SetupDefaults(reg);
            var profileManager = reg.Get<IProfileManager>();
            profileManager.RegisterOrganization(Arg.Any<OrganizationRegistrationData>())
                .Returns(new OrganizationData { Handle = "org-001", Name = "Acme Corp" });
        })
        .When<IUserAccountService>("registers an organization", (svc) =>
        {
            return svc.RegisterOrganization(new OrganizationRegistrationData
            {
                Name = "Acme Corp",
                Handle = "org-001"
            });
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<RegistrationResult>("succeeds", r => r!.Success);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RegisterAgentWithValidData()
    {
        After.Setup(reg =>
        {
            SetupDefaults(reg);
            var profileManager = reg.Get<IProfileManager>();
            profileManager.RegisterAgent(Arg.Any<AgentRegistrationData>())
                .Returns(new AgentData { Handle = "agent-001", Name = "Bot Agent" });
        })
        .When<IUserAccountService>("registers an agent", (svc) =>
        {
            return svc.RegisterAgent(new AgentRegistrationData
            {
                Name = "Bot Agent",
                Handle = "agent-001",
                PersonHandle = "person-abc",
                DeviceHandle = "device-001"
            });
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<RegistrationResult>("succeeds", r => r!.Success);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectAgentRegistrationWithMissingPersonHandle()
    {
        After.Setup(SetupDefaults)
        .When<IUserAccountService>("registers an agent without person handle", (svc) =>
        {
            return svc.RegisterAgent(new AgentRegistrationData
            {
                Name = "Bot Agent",
                Handle = "agent-001",
                PersonHandle = "",
                DeviceHandle = "device-001"
            });
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<RegistrationResult>("fails", r => !r!.Success)
                .As<RegistrationResult>("has error about PersonHandle", r => r!.Message.Contains("PersonHandle"));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void GetProfileByHandle()
    {
        After.Setup(SetupDefaults)
        .When<IUserAccountService>("gets a profile by handle", (svc) =>
        {
            return svc.GetProfile("person-abc");
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<IProfile>("has correct name", p => p!.Name == "Jane Doe")
                .As<IProfile>("has correct person handle", p => p!.PersonHandle == "person-abc");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void UpdateProfile()
    {
        After.Setup(reg =>
        {
            SetupDefaults(reg);
            var profileRepo = reg.Get<IProfileRepository>();
            var profileData = new ProfileData
            {
                ProfileHandle = "profile-123",
                PersonHandle = "person-abc",
                Name = "Jane Doe",
                ShowEmail = false,
                ShowPhone = false
            };
            profileRepo.FindProfileByHandle("profile-123").Returns(profileData);
            profileRepo.SaveProfile(Arg.Any<ProfileData>()).Returns(callInfo => callInfo.Arg<ProfileData>());
        })
        .When<IUserAccountService>("updates a profile", (svc) =>
        {
            return svc.UpdateProfile("profile-123", p =>
            {
                p.ShowEmail = true;
                p.ShowPhone = true;
            });
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult.IsNotNull();

            var profileRepo = because.TestCaseRegistry.Get<IProfileRepository>();
            profileRepo.Received(1).SaveProfile(Arg.Is<ProfileData>(p => p.ShowEmail && p.ShowPhone));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void DelegateConfirmationToIAccountConfirmation()
    {
        After.Setup(reg =>
        {
            SetupDefaults(reg);
            var confirmation = reg.Get<IAccountConfirmation>();
            confirmation.CreateChallenge("person-abc")
                .Returns(new ConfirmationChallenge
                {
                    PersonHandle = "person-abc",
                    ChallengeBytes = new byte[] { 1, 2, 3 },
                    ExpiresUtc = DateTime.UtcNow.AddMinutes(10)
                });
        })
        .When<IUserAccountService>("initiates confirmation", (svc) =>
        {
            return svc.InitiateConfirmation("person-abc");
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<ConfirmationChallenge>("has correct person handle", c => c!.PersonHandle == "person-abc")
                .As<ConfirmationChallenge>("has challenge bytes", c => c!.ChallengeBytes.Length > 0)
                .As<ConfirmationChallenge>("has future expiration", c => c!.ExpiresUtc > DateTime.UtcNow);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void NotifyAfterSuccessfulConfirmation()
    {
        After.Setup(reg =>
        {
            SetupDefaults(reg);
            var confirmation = reg.Get<IAccountConfirmation>();
            confirmation.VerifySignedChallenge("person-abc", Arg.Any<byte[]>())
                .Returns(new ConfirmationResult { Confirmed = true, Success = true });
        })
        .When<IUserAccountService>("confirms an account", (svc) =>
        {
            return svc.ConfirmAccount("person-abc", new byte[] { 1, 2, 3 });
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<ConfirmationResult>("is confirmed", r => r!.Confirmed);

            var notifier = because.TestCaseRegistry.Get<IRegistrationNotifier>();
            notifier.Received(1).OnAccountConfirmed(Arg.Any<IProfile>());
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void DelegateRoleAssignmentToRoleGroupMapper()
    {
        After.Setup(SetupDefaults)
        .When<IUserAccountService>("assigns roles to a person", (svc) =>
        {
            svc.AssignRoles("person-abc", "admin", "editor");
            return svc.GetRoles("person-abc");
        })
        .TheTest
        .ShouldPass(because =>
        {
            var mapper = because.TestCaseRegistry.Get<IRoleGroupMapper>();
            mapper.Received(1).AssignRolesToPerson("person-abc", "admin", "editor");
            mapper.Received(1).GetRolesForPerson("person-abc");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void DelegateRoleRemovalToRoleGroupMapper()
    {
        After.Setup(SetupDefaults)
        .When<IUserAccountService>("removes roles from a person", (svc) =>
        {
            svc.RemoveRoles("person-abc", "editor");
            return true;
        })
        .TheTest
        .ShouldPass(because =>
        {
            var mapper = because.TestCaseRegistry.Get<IRoleGroupMapper>();
            mapper.Received(1).RemoveRolesFromPerson("person-abc", "editor");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}
