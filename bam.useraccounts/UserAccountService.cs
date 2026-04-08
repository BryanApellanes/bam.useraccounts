using Bam.Protocol;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Common;
using Bam.Protocol.Data.Profile;
using Bam.Protocol.Data.Server;
using Bam.Protocol.Profile;
using Bam.Protocol.Profile.Registration;

namespace Bam.UserAccounts;

public class UserAccountService : IUserAccountService
{
    private readonly IAccountManager _accountManager;
    private readonly IProfileManager _profileManager;
    private readonly IProfileRepository _profileRepository;
    private readonly IRegistrationValidator _validator;
    private readonly IRegistrationNotifier _notifier;
    private readonly IAccountConfirmation _confirmation;
    private readonly IRoleGroupMapper _roleGroupMapper;

    public UserAccountService(
        IAccountManager accountManager,
        IProfileManager profileManager,
        IProfileRepository profileRepository,
        IRegistrationValidator validator,
        IRegistrationNotifier notifier,
        IAccountConfirmation confirmation,
        IRoleGroupMapper roleGroupMapper)
    {
        _accountManager = accountManager;
        _profileManager = profileManager;
        _profileRepository = profileRepository;
        _validator = validator;
        _notifier = notifier;
        _confirmation = confirmation;
        _roleGroupMapper = roleGroupMapper;
    }

    public RegistrationResult RegisterPerson(PersonRegistrationData data)
    {
        var validation = _validator.Validate(data);
        if (!validation.IsValid)
        {
            return new RegistrationResult
            {
                Success = false,
                Message = string.Join("; ", validation.Errors)
            };
        }

        var account = _accountManager.RegisterAccount(data);
        var profile = _profileManager.FindProfileByHandle(account.PersonHandle);
        _notifier.OnPersonRegistered(profile, account);

        return new RegistrationResult
        {
            Success = true,
            AccountData = account,
            Profile = profile
        };
    }

    public RegistrationResult RegisterDevice(DeviceRegistrationData data, string personHandle)
    {
        var validation = _validator.Validate(data);
        if (!validation.IsValid)
        {
            return new RegistrationResult
            {
                Success = false,
                Message = string.Join("; ", validation.Errors)
            };
        }

        var profile = _profileManager.RegisterDeviceProfile(data, personHandle);
        var device = _profileManager.FindDeviceByHandle(data.Handle);
        _notifier.OnDeviceRegistered(profile, device);

        return new RegistrationResult
        {
            Success = true,
            Profile = profile
        };
    }

    public RegistrationResult RegisterOrganization(OrganizationRegistrationData data)
    {
        var validation = _validator.Validate(data);
        if (!validation.IsValid)
        {
            return new RegistrationResult
            {
                Success = false,
                Message = string.Join("; ", validation.Errors)
            };
        }

        _profileManager.RegisterOrganization(data);
        return new RegistrationResult { Success = true };
    }

    public RegistrationResult RegisterAgent(AgentRegistrationData data)
    {
        var validation = _validator.Validate(data);
        if (!validation.IsValid)
        {
            return new RegistrationResult
            {
                Success = false,
                Message = string.Join("; ", validation.Errors)
            };
        }

        _profileManager.RegisterAgent(data);
        return new RegistrationResult { Success = true };
    }

    public IProfile? GetProfile(string handle)
    {
        return _profileManager.FindProfileByHandle(handle);
    }

    public IProfile UpdateProfile(string handle, Action<ProfileData> update)
    {
        var profileData = _profileRepository.FindProfileByHandle(handle);
        update(profileData);
        _profileRepository.SaveProfile(profileData);
        return profileData;
    }

    public ConfirmationChallenge InitiateConfirmation(string personHandle)
    {
        return _confirmation.CreateChallenge(personHandle);
    }

    public ConfirmationResult ConfirmAccount(string personHandle, byte[] signedChallenge)
    {
        var result = _confirmation.VerifySignedChallenge(personHandle, signedChallenge);
        if (result.Confirmed)
        {
            var profile = _profileManager.FindProfileByHandle(personHandle);
            _notifier.OnAccountConfirmed(profile);
        }
        return result;
    }

    public void AssignRoles(string personHandle, params string[] roleNames)
    {
        _roleGroupMapper.AssignRolesToPerson(personHandle, roleNames);
    }

    public void RemoveRoles(string personHandle, params string[] roleNames)
    {
        _roleGroupMapper.RemoveRolesFromPerson(personHandle, roleNames);
    }

    public string[] GetRoles(string personHandle)
    {
        return _roleGroupMapper.GetRolesForPerson(personHandle);
    }
}
