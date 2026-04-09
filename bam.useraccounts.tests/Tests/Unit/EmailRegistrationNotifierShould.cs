using Bam.DependencyInjection;
using Bam.Messaging;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Common;
using Bam.Protocol.Data.Profile;
using Bam.Protocol.Data.Server;
using Bam.Test;
using Bam.UserAccounts;
using NSubstitute;

namespace Bam.UserAccounts.Tests.Unit;

[UnitTestMenu("EmailRegistrationNotifier Should", Selector = "ern")]
public class EmailRegistrationNotifierShould : UnitTestMenuContainer
{
    public EmailRegistrationNotifierShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    private static IProfile CreateMockProfile(string name = "Jane Doe", string personHandle = "person-abc")
    {
        var profile = Substitute.For<IProfile>();
        profile.Name.Returns(name);
        profile.PersonHandle.Returns(personHandle);
        return profile;
    }

    private static TestableEmailComposer CreateComposer(bool welcomeExists = false, bool deviceExists = false, bool confirmedExists = false)
    {
        return new TestableEmailComposer(welcomeExists, deviceExists, confirmedExists);
    }

    [UnitTest]
    public void CheckWelcomeTemplateOnPersonRegistered()
    {
        var composer = CreateComposer(welcomeExists: true);

        When.A<EmailRegistrationNotifier>("notifies on person registration",
            () => new EmailRegistrationNotifier(composer),
            (notifier) =>
            {
                notifier.OnPersonRegistered(
                    CreateMockProfile(),
                    new AccountData { PersonHandle = "person-abc" });
                return composer.ComposeCalledWith;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheObjectUnderTest
                .IsNotNull()
                .IsObjectOfType<EmailRegistrationNotifier>();

            because.ItsTrue("Compose was called with WelcomeEmail",
                composer.ComposeCalledWith == "WelcomeEmail");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void SkipWelcomeEmailWhenTemplateNotFound()
    {
        var composer = CreateComposer(welcomeExists: false);

        When.A<EmailRegistrationNotifier>("notifies without welcome template",
            () => new EmailRegistrationNotifier(composer),
            (notifier) =>
            {
                notifier.OnPersonRegistered(
                    CreateMockProfile(),
                    new AccountData { PersonHandle = "person-abc" });
                return true;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("Compose was not called",
                composer.ComposeCalledWith == null);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ComposeDeviceEmailOnDeviceRegistered()
    {
        var composer = CreateComposer(deviceExists: true);

        When.A<EmailRegistrationNotifier>("notifies on device registration",
            () => new EmailRegistrationNotifier(composer),
            (notifier) =>
            {
                notifier.OnDeviceRegistered(
                    CreateMockProfile(),
                    new DeviceData { Handle = "device-001", Name = "My Laptop" });
                return composer.ComposeCalledWith;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("Compose was called with DeviceRegisteredEmail",
                composer.ComposeCalledWith == "DeviceRegisteredEmail");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ComposeConfirmationEmailOnAccountConfirmed()
    {
        var composer = CreateComposer(confirmedExists: true);

        When.A<EmailRegistrationNotifier>("notifies on account confirmation",
            () => new EmailRegistrationNotifier(composer),
            (notifier) =>
            {
                notifier.OnAccountConfirmed(CreateMockProfile());
                return composer.ComposeCalledWith;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("Compose was called with AccountConfirmedEmail",
                composer.ComposeCalledWith == "AccountConfirmedEmail");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void SkipAllEmailsWhenNoTemplatesExist()
    {
        var composer = CreateComposer(welcomeExists: false, deviceExists: false, confirmedExists: false);

        When.A<EmailRegistrationNotifier>("notifies without any templates",
            () => new EmailRegistrationNotifier(composer),
            (notifier) =>
            {
                notifier.OnPersonRegistered(CreateMockProfile(), new AccountData { PersonHandle = "p" });
                notifier.OnDeviceRegistered(CreateMockProfile(), new DeviceData { Handle = "d" });
                notifier.OnAccountConfirmed(CreateMockProfile());
                return true;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("Compose was never called",
                composer.ComposeCalledWith == null);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}

internal class TestableEmailComposer : EmailComposer
{
    private readonly Dictionary<string, bool> _templateExistence;

    public string? ComposeCalledWith { get; private set; }

    public TestableEmailComposer(bool welcomeExists, bool deviceExists, bool confirmedExists)
        : base(".")
    {
        _templateExistence = new Dictionary<string, bool>
        {
            ["WelcomeEmail"] = welcomeExists,
            ["DeviceRegisteredEmail"] = deviceExists,
            ["AccountConfirmedEmail"] = confirmedExists,
        };
    }

    public override bool TemplateExists(string emailName)
    {
        return _templateExistence.TryGetValue(emailName, out var exists) && exists;
    }

    public override string GetEmailBody(string emailName, params object[] data)
    {
        ComposeCalledWith = emailName;
        return $"[test body for {emailName}]";
    }

    public override EmailTemplate GetTemplate(string templateName)
    {
        return new EmailTemplate { EmailName = templateName, IsHtml = false, TemplateContent = "" };
    }
}
