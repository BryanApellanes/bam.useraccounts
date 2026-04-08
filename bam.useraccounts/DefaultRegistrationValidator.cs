using Bam.Protocol.Profile.Registration;

namespace Bam.UserAccounts;

public class DefaultRegistrationValidator : IRegistrationValidator
{
    public ValidationResult Validate(PersonRegistrationData data)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(data.FirstName))
            errors.Add("FirstName is required");

        if (string.IsNullOrWhiteSpace(data.LastName))
            errors.Add("LastName is required");

        return errors.Count == 0
            ? ValidationResult.Valid()
            : ValidationResult.Invalid(errors.ToArray());
    }

    public ValidationResult Validate(DeviceRegistrationData data)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(data.Name))
            errors.Add("Device name is required");

        return errors.Count == 0
            ? ValidationResult.Valid()
            : ValidationResult.Invalid(errors.ToArray());
    }

    public ValidationResult Validate(OrganizationRegistrationData data)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(data.Name))
            errors.Add("Organization name is required");

        return errors.Count == 0
            ? ValidationResult.Valid()
            : ValidationResult.Invalid(errors.ToArray());
    }

    public ValidationResult Validate(AgentRegistrationData data)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(data.Name))
            errors.Add("Agent name is required");

        if (string.IsNullOrWhiteSpace(data.PersonHandle))
            errors.Add("PersonHandle is required");

        if (string.IsNullOrWhiteSpace(data.DeviceHandle))
            errors.Add("DeviceHandle is required");

        return errors.Count == 0
            ? ValidationResult.Valid()
            : ValidationResult.Invalid(errors.ToArray());
    }
}
