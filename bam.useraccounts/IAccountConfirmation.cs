namespace Bam.UserAccounts;

public interface IAccountConfirmation
{
    ConfirmationChallenge CreateChallenge(string personHandle);
    ConfirmationResult VerifySignedChallenge(string personHandle, byte[] signedChallenge);
}
