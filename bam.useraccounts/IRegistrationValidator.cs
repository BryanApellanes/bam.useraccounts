using Bam.Protocol.Profile.Registration;

namespace Bam.UserAccounts;

public interface IRegistrationValidator
{
    ValidationResult Validate(PersonRegistrationData data);
    ValidationResult Validate(DeviceRegistrationData data);
    ValidationResult Validate(OrganizationRegistrationData data);
    ValidationResult Validate(AgentRegistrationData data);
}
