using Bam.Messaging;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Common;
using Bam.Protocol.Data.Profile;
using Bam.Protocol.Data.Server;

namespace Bam.UserAccounts;

public class EmailRegistrationNotifier : IRegistrationNotifier
{
    private readonly EmailComposer _emailComposer;

    public EmailRegistrationNotifier(EmailComposer emailComposer)
    {
        _emailComposer = emailComposer;
    }

    public void OnPersonRegistered(IProfile profile, AccountData account)
    {
        if (_emailComposer.TemplateExists("WelcomeEmail"))
        {
            _emailComposer.Compose(
                "Welcome",
                "WelcomeEmail",
                new { Name = profile.Name, PersonHandle = account.PersonHandle }
            );
        }
    }

    public void OnDeviceRegistered(IProfile profile, DeviceData device)
    {
        if (_emailComposer.TemplateExists("DeviceRegisteredEmail"))
        {
            _emailComposer.Compose(
                "Device Registered",
                "DeviceRegisteredEmail",
                new { Name = profile.Name, DeviceHandle = device.Handle }
            );
        }
    }

    public void OnAccountConfirmed(IProfile profile)
    {
        if (_emailComposer.TemplateExists("AccountConfirmedEmail"))
        {
            _emailComposer.Compose(
                "Account Confirmed",
                "AccountConfirmedEmail",
                new { Name = profile.Name }
            );
        }
    }
}
