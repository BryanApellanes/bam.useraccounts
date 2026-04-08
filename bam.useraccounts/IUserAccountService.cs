using Bam.Protocol.Data;
using Bam.Protocol.Data.Common;
using Bam.Protocol.Data.Profile;
using Bam.Protocol.Profile.Registration;

namespace Bam.UserAccounts;

public interface IUserAccountService
{
    RegistrationResult RegisterPerson(PersonRegistrationData data);
    RegistrationResult RegisterDevice(DeviceRegistrationData data, string personHandle);
    RegistrationResult RegisterOrganization(OrganizationRegistrationData data);
    RegistrationResult RegisterAgent(AgentRegistrationData data);

    IProfile? GetProfile(string handle);
    IProfile UpdateProfile(string handle, Action<ProfileData> update);

    ConfirmationChallenge InitiateConfirmation(string personHandle);
    ConfirmationResult ConfirmAccount(string personHandle, byte[] signedChallenge);

    void AssignRoles(string personHandle, params string[] roleNames);
    void RemoveRoles(string personHandle, params string[] roleNames);
    string[] GetRoles(string personHandle);
}
