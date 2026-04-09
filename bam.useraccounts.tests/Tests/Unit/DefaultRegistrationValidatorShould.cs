using Bam.DependencyInjection;
using Bam.Protocol.Profile.Registration;
using Bam.Test;
using Bam.UserAccounts;

namespace Bam.UserAccounts.Tests.Unit;

[UnitTestMenu("DefaultRegistrationValidator Should", Selector = "drv")]
public class DefaultRegistrationValidatorShould : UnitTestMenuContainer
{
    public DefaultRegistrationValidatorShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    [UnitTest]
    public void AcceptValidPersonData()
    {
        When.A<DefaultRegistrationValidator>("validates a valid person registration",
            () => new DefaultRegistrationValidator(),
            (validator) => validator.Validate(new PersonRegistrationData
            {
                FirstName = "Jane",
                LastName = "Doe",
                Email = "jane@example.com"
            }))
        .TheTest
        .ShouldPass(because =>
        {
            because.TheObjectUnderTest
                .IsNotNull()
                .IsObjectOfType<DefaultRegistrationValidator>();

            because.TheResult
                .IsNotNull()
                .As<ValidationResult>("is valid", r => r!.IsValid)
                .As<ValidationResult>("has no errors", r => r!.Errors.Count == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectPersonDataWithEmptyFirstName()
    {
        When.A<DefaultRegistrationValidator>("validates person data with empty first name",
            () => new DefaultRegistrationValidator(),
            (validator) => validator.Validate(new PersonRegistrationData
            {
                FirstName = "",
                LastName = "Doe"
            }))
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<ValidationResult>("is invalid", r => !r!.IsValid)
                .As<ValidationResult>("has one error", r => r!.Errors.Count == 1)
                .As<ValidationResult>("error mentions FirstName", r => r!.Errors[0].Contains("FirstName"));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectPersonDataWithEmptyLastName()
    {
        When.A<DefaultRegistrationValidator>("validates person data with empty last name",
            () => new DefaultRegistrationValidator(),
            (validator) => validator.Validate(new PersonRegistrationData
            {
                FirstName = "Jane",
                LastName = "  "
            }))
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<ValidationResult>("is invalid", r => !r!.IsValid)
                .As<ValidationResult>("error mentions LastName", r => r!.Errors[0].Contains("LastName"));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectPersonDataWithBothFieldsMissing()
    {
        When.A<DefaultRegistrationValidator>("validates person data with both names empty",
            () => new DefaultRegistrationValidator(),
            (validator) => validator.Validate(new PersonRegistrationData
            {
                FirstName = "",
                LastName = ""
            }))
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<ValidationResult>("is invalid", r => !r!.IsValid)
                .As<ValidationResult>("has two errors", r => r!.Errors.Count == 2);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void AcceptPersonDataWithOptionalFieldsEmpty()
    {
        When.A<DefaultRegistrationValidator>("validates person data without optional fields",
            () => new DefaultRegistrationValidator(),
            (validator) => validator.Validate(new PersonRegistrationData
            {
                FirstName = "Jane",
                LastName = "Doe",
                Email = "",
                Phone = "",
                Handle = ""
            }))
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<ValidationResult>("is valid", r => r!.IsValid);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void AcceptValidDeviceData()
    {
        When.A<DefaultRegistrationValidator>("validates valid device data",
            () => new DefaultRegistrationValidator(),
            (validator) => validator.Validate(new DeviceRegistrationData
            {
                Name = "My Laptop",
                Handle = "device-001"
            }))
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<ValidationResult>("is valid", r => r!.IsValid);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectDeviceDataWithEmptyName()
    {
        When.A<DefaultRegistrationValidator>("validates device data with empty name",
            () => new DefaultRegistrationValidator(),
            (validator) => validator.Validate(new DeviceRegistrationData
            {
                Name = "",
                Handle = "device-001"
            }))
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<ValidationResult>("is invalid", r => !r!.IsValid)
                .As<ValidationResult>("error mentions device name", r => r!.Errors[0].Contains("Device name"));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void AcceptValidOrganizationData()
    {
        When.A<DefaultRegistrationValidator>("validates valid organization data",
            () => new DefaultRegistrationValidator(),
            (validator) => validator.Validate(new OrganizationRegistrationData
            {
                Name = "Acme Corp",
                Handle = "acme"
            }))
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<ValidationResult>("is valid", r => r!.IsValid);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectOrganizationDataWithEmptyName()
    {
        When.A<DefaultRegistrationValidator>("validates organization data with empty name",
            () => new DefaultRegistrationValidator(),
            (validator) => validator.Validate(new OrganizationRegistrationData
            {
                Name = "",
                Handle = "acme"
            }))
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<ValidationResult>("is invalid", r => !r!.IsValid)
                .As<ValidationResult>("error mentions organization name", r => r!.Errors[0].Contains("Organization name"));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void AcceptValidAgentData()
    {
        When.A<DefaultRegistrationValidator>("validates valid agent data",
            () => new DefaultRegistrationValidator(),
            (validator) => validator.Validate(new AgentRegistrationData
            {
                Name = "Bot Agent",
                Handle = "agent-001",
                PersonHandle = "person-abc",
                DeviceHandle = "device-001"
            }))
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<ValidationResult>("is valid", r => r!.IsValid);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectAgentDataWithMissingRequiredFields()
    {
        When.A<DefaultRegistrationValidator>("validates agent data with missing fields",
            () => new DefaultRegistrationValidator(),
            (validator) => validator.Validate(new AgentRegistrationData
            {
                Name = "",
                Handle = "agent-001",
                PersonHandle = "",
                DeviceHandle = ""
            }))
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<ValidationResult>("is invalid", r => !r!.IsValid)
                .As<ValidationResult>("has three errors", r => r!.Errors.Count == 3);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}
