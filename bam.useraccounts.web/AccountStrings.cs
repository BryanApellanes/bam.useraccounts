using System.Reflection;

namespace Bam.UserAccounts.Web;

/// <summary>
/// Every string the account pages and the browser module show, with English defaults.  A host
/// overrides the members it wants to reword or translate.
/// </summary>
public sealed class AccountStrings
{
    /// <summary>Sign-up page heading.</summary>
    public string SignUpTitle { get; set; } = "Create your account";

    /// <summary>Sign-in page heading.</summary>
    public string SignInTitle { get; set; } = "Sign in";

    /// <summary>Manage page heading.</summary>
    public string ManageTitle { get; set; } = "Your passkeys";

    /// <summary>Signed-out page heading.</summary>
    public string SignedOutTitle { get; set; } = "You're signed out";

    /// <summary>Label of the handle field.</summary>
    public string HandleLabel { get; set; } = "Handle";

    /// <summary>Help text under the handle field.</summary>
    public string HandleHelp { get; set; } = "3 to 32 characters: lowercase letters, digits and hyphens.";

    /// <summary>Label of the display-name field.</summary>
    public string DisplayNameLabel { get; set; } = "Name";

    /// <summary>Label of the email field.</summary>
    public string EmailLabel { get; set; } = "Email";

    /// <summary>Suffix on the email label when email is optional.</summary>
    public string OptionalSuffix { get; set; } = "(optional)";

    /// <summary>Label of the invite-code field.</summary>
    public string InviteCodeLabel { get; set; } = "Invite code";

    /// <summary>The sign-up button.</summary>
    public string CreatePasskey { get; set; } = "Create passkey";

    /// <summary>The sign-in button.</summary>
    public string SignInWithPasskey { get; set; } = "Sign in with a passkey";

    /// <summary>Label of the optional handle field on the sign-in page.</summary>
    public string SignInHandleLabel { get; set; } = "Handle (optional)";

    /// <summary>The add-a-passkey button on the manage page.</summary>
    public string AddPasskey { get; set; } = "Add a passkey";

    /// <summary>Label of the name field beside the add button.</summary>
    public string PasskeyNameLabel { get; set; } = "Passkey name";

    /// <summary>The rename button.</summary>
    public string Rename { get; set; } = "Rename";

    /// <summary>The remove button.</summary>
    public string Remove { get; set; } = "Remove";

    /// <summary>The sign-out button.</summary>
    public string SignOut { get; set; } = "Sign out";

    /// <summary>Link from sign-up to sign-in.</summary>
    public string HaveAccount { get; set; } = "Already have an account? Sign in";

    /// <summary>Link from sign-in to sign-up.</summary>
    public string NeedAccount { get; set; } = "New here? Create an account";

    /// <summary>Shown on the sign-up page when sign-up is closed.</summary>
    public string SignUpClosed { get; set; } = "Sign-up is closed right now.";

    /// <summary>Shown when the chosen handle is taken.</summary>
    public string HandleTakenMessage { get; set; } = "That handle is taken. Try another.";

    /// <summary>Shown when the chosen handle does not fit the rules.</summary>
    public string HandleInvalidMessage { get; set; } = "That handle can't be used. Use lowercase letters, digits and hyphens.";

    /// <summary>Shown when the handle is free.</summary>
    public string HandleAvailableMessage { get; set; } = "That handle is available.";

    /// <summary>Shown when an invite code is missing or wrong.</summary>
    public string InviteRequiredMessage { get; set; } = "A valid invite code is required.";

    /// <summary>Shown when an email address is required and missing or malformed.</summary>
    public string EmailRequiredMessage { get; set; } = "Enter a valid email address.";

    /// <summary>Shown when sign-up fails for a reason the page does not disclose.</summary>
    public string SignUpFailedMessage { get; set; } = "We couldn't create your account. Try again.";

    /// <summary>Shown when sign-in fails.  The same text for every cause.</summary>
    public string SignInFailedMessage { get; set; } = "We couldn't sign you in with that passkey.";

    /// <summary>Shown when the person cancels the browser's passkey prompt or it times out.</summary>
    public string CancelledMessage { get; set; } = "The passkey prompt was dismissed. Try again when you're ready.";

    /// <summary>Shown when the browser has no passkey support.</summary>
    public string UnsupportedMessage { get; set; } = "This browser doesn't support passkeys.";

    /// <summary>Shown when too many requests were made.</summary>
    public string RateLimitedMessage { get; set; } = "Too many attempts. Wait a minute and try again.";

    /// <summary>Shown when a manage-page action fails.</summary>
    public string ActionFailedMessage { get; set; } = "That didn't work. Reload the page and try again.";

    /// <summary>Shown when the person tries to remove their only passkey.</summary>
    public string LastPasskeyMessage { get; set; } = "This is your only passkey. Add another before removing it.";

    /// <summary>Asked when the passkey being removed holds the account's key (bam.useraccounts#20).</summary>
    public string KeySetHandoverPrompt { get; set; } = "This passkey holds your account's key. Confirm with it once to move the key to another of your passkeys, then it's removed.";

    /// <summary>Asked when the key can't be moved first: the passkey is removed and the key stays with it.</summary>
    public string KeySetKeepConfirmation { get; set; } = "This passkey holds your account's key, and moving it needs that passkey. Remove it anyway? The key stays on record until you replace it.";

    /// <summary>The badge on the passkey that holds the account's key.</summary>
    public string KeySetBadge { get; set; } = "Account key";

    /// <summary>Under the key-set passkey when removing it moves the key first.</summary>
    public string KeySetMovesNote { get; set; } = "Removing it moves the key to another of your passkeys first.";

    /// <summary>Under the key-set passkey when the key can't be moved: removing it leaves the key on record.</summary>
    public string KeySetStaysNote { get; set; } = "Removing it doesn't move the key. The key stays on record until it's replaced.";

    /// <summary>Shown when moving the key didn't go through.</summary>
    public string HandoverFailedMessage { get; set; } = "The key didn't move and nothing was removed. Reload the page and try again.";

    /// <summary>Shown while a ceremony is running.</summary>
    public string WorkingMessage { get; set; } = "Waiting for your passkey...";

    /// <summary>Asked before a passkey is removed.</summary>
    public string RemoveConfirmation { get; set; } = "Remove this passkey? It will stop working for sign-in.";

    /// <summary>Marks the passkey this session signed in with.</summary>
    public string CurrentPasskeyBadge { get; set; } = "This device";

    /// <summary>Shown for a passkey without a name.</summary>
    public string UnnamedPasskey { get; set; } = "Passkey";

    /// <summary>Prefix of a passkey's creation date.</summary>
    public string AddedPrefix { get; set; } = "Added";

    /// <summary>Prefix of a passkey's last-use date.</summary>
    public string LastUsedPrefix { get; set; } = "Last used";

    /// <summary>Shown on the manage page when the person's profile was not written at sign-up.</summary>
    public string ProfileIncompleteMessage { get; set; } = "Your profile wasn't saved when you signed up. Check your details and save them.";

    /// <summary>The button that saves a profile that wasn't saved at sign-up.</summary>
    public string SaveProfile { get; set; } = "Save profile";

    /// <summary>Shown when saving the profile failed.</summary>
    public string ProfileNotSavedMessage { get; set; } = "We couldn't save your profile. Try again later.";

    /// <summary>Body of the signed-out page.</summary>
    public string SignedOutMessage { get; set; } = "Come back any time.";

    /// <summary>Terms link text.</summary>
    public string TermsLink { get; set; } = "Terms";

    /// <summary>Privacy link text.</summary>
    public string PrivacyLink { get; set; } = "Privacy";

    /// <summary>Support link text.</summary>
    public string SupportLink { get; set; } = "Support";

    /// <summary>Throws <see cref="InvalidOperationException"/> naming a string that was set to null.</summary>
    public void Validate()
    {
        foreach (PropertyInfo property in typeof(AccountStrings).GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (property.PropertyType == typeof(string) && property.GetValue(this) is null)
            {
                throw new InvalidOperationException($"AccountStrings.{property.Name} must not be null (use an empty string to show nothing).");
            }
        }
    }
}
