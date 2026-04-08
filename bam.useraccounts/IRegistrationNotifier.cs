using Bam.Protocol.Data;
using Bam.Protocol.Data.Common;
using Bam.Protocol.Data.Profile;
using Bam.Protocol.Data.Server;

namespace Bam.UserAccounts;

public interface IRegistrationNotifier
{
    void OnPersonRegistered(IProfile profile, AccountData account);
    void OnDeviceRegistered(IProfile profile, DeviceData device);
    void OnAccountConfirmed(IProfile profile);
}
