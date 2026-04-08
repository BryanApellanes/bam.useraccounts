# bam.useraccounts + bam.protocol Integration Plan

**Date:** 2026-04-08  
**Status:** Implemented

## Goal

Make `bam.useraccounts` the single entry point for user account and profile registration management, built on top of `bam.protocol` primitives. All existing code in `bam.useraccounts` is considered deprecated and replaced.

## Design Decisions

1. **Credential interfaces** (`ICredentialProvider`, etc.) — kept as separate concern, untouched
2. **Role system** — bridged to `bam.protocol` groups via `IRoleGroupMapper` (maps role names to `GroupData` + `BamAccess`)
3. **Account confirmation** — device-key-based (ECDSA signature verification), not email tokens
4. **Password flows** — dropped entirely (no passwords in PKI-based design)
5. **Authentication** — remains in `bam.protocol` pipeline; `bam.useraccounts` owns account lifecycle only
6. **Dependencies** — `bam.useraccounts` now references `bam.protocol.data`, `bam.protocol.profile`, `bam.encryption`

## Architecture

```
bamsvc (HTTP layer)
  └── RegistrationService → IUserAccountService

bam.useraccounts (orchestration layer)
  ├── IUserAccountService     ← single entry point (facade)
  ├── IRegistrationValidator  ← input validation
  ├── IRegistrationNotifier   ← post-registration side effects
  ├── IAccountConfirmation    ← device-key confirmation
  └── IRoleGroupMapper        ← role-to-group bridge

bam.protocol (primitives — unchanged)
  ├── IAccountManager, IProfileManager
  ├── IProfileRepository (extended with group methods)
  ├── ICertificateManager, IKeyManager
  └── registration data types, crypto, sessions
```

## New Interfaces

| Interface | Responsibility |
|-----------|---------------|
| `IUserAccountService` | Facade: registration, profile, confirmation, roles |
| `IRegistrationValidator` | Validates registration input data |
| `IRegistrationNotifier` | Side effects after registration events (email, etc.) |
| `IAccountConfirmation` | Device-key challenge/response confirmation |
| `IRoleGroupMapper` | Maps role names to bam.protocol GroupData + BamAccess |

## New Implementations

| Class | Implements |
|-------|-----------|
| `UserAccountService` | `IUserAccountService` |
| `DefaultRegistrationValidator` | `IRegistrationValidator` |
| `EmailRegistrationNotifier` | `IRegistrationNotifier` |
| `DeviceKeyAccountConfirmation` | `IAccountConfirmation` |
| `RoleGroupMapper` | `IRoleGroupMapper` |

## New Data Types

| Type | Purpose |
|------|---------|
| `RegistrationResult` | Result of any registration operation |
| `ConfirmationChallenge` | Challenge bytes for device-key confirmation |
| `ConfirmationResult` | Result of confirmation with optional certificate |
| `ValidationResult` | Input validation result with error list |

## Changes to bam.protocol

- `IProfileRepository` extended with: `SaveGroup`, `FindGroupByName`, `GetGroupsForPerson`, `AddPersonToGroup`, `RemovePersonFromGroup`
- `EncryptedProfileRepository` implements the new methods

## Changes to bamsvc

- `RegistrationService` now injects `IUserAccountService` instead of `IAccountManager`/`IProfileManager` directly
- `Program.cs` registers all new services in `ComponentRegistry`
- `bamsvc.csproj` references `bam.useraccounts`
- Return type of `RegisterPerson` changed from `AccountData` to `RegistrationResult`

## Deleted (deprecated)

- All `Dao*` classes, `UserManager`, `UserManagerEventArgs`
- `UserAccounts_Generated/` directory and `UserAccounts.db.js` schema
- `IAuthenticator`, `Authenticator`, `CompositeAuthenticator` (SHA1-based)
- `IUserProvider`, `IDaoUserResolver`, `UserInfo`, `UserAccountsDatabase`
- Password/login/signout response types
- `_UserAccounts/` directory

## Kept (unchanged)

- Credential interfaces and implementations (separate concern)
- `EmailComposer`, `NamedFormatEmailComposer`, `EmailTemplate`
- `RoleRequiredAttribute`, `IRoleResolver`, `IRoleProvider`, `IRoleReader`
- `UserAccountResponse` (base class), `CheckEmailResponse`, `CheckUserNameResponse`, `ConfirmResponse`, `SendEmailResponse`, `SignUpResponse`
- Exception types: `AccountCreationFailedException`, `EmailAlreadyRegisteredException`, `UserNameInUseException`, `UserNameNotFoundException`
