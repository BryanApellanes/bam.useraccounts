using System.Text;
using Bam.Data.Dynamic.Objects;
using Bam.Data.Objects;
using Bam.Encryption;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Profile;
using Bam.Protocol.Profile;
using Bam.Storage;
using Bam.UserAccounts.Passkeys;

namespace Bam.UserAccounts.Tests.TestClasses;

/// <summary>
/// The key-set handover over a real <see cref="PublicKeySetRegistrar"/> and proof chain
/// (bam.protocol#72), so a test sees exactly what bam.protocol would: which key set the handle
/// resolves to, and whether a retired key is blocklisted.
/// </summary>
public sealed class HandoverFixture
{
    public const string Handle = "person-abc";

    public HandoverFixture(string testName, bool trustPasskeyProof = true)
    {
        Options = PasskeyFixture.DefaultOptions();
        Challenges = new InMemoryConfirmationChallengeRepository();
        Credentials = new InMemoryPasskeyCredentialRepository();
        Proofs = KeySetRotationProofChain.DefaultProofs();
        Registrar = new PublicKeySetRegistrar(CreateObjectDataRepository(testName), new KeySetRotationProofChain(Proofs));
        Ceremony = new PasskeyCeremony(Options, Challenges, Credentials, new PasskeyRegistrationVerifier(Options), new PasskeyAssertionVerifier(Options, new DetachedSignatureVerifier()), Registrar);
        Proof = new PasskeyKeySetRotationProof(Credentials, Ceremony);
        if (trustPasskeyProof)
        {
            Proofs.Add(Proof);
        }
        Handover = new KeySetHandover(Credentials, Registrar, Proofs, Challenges, Options);
        Inventory = new PasskeyInventory(Credentials, Handover);
    }

    public PasskeyOptions Options { get; }
    public InMemoryConfirmationChallengeRepository Challenges { get; }
    public InMemoryPasskeyCredentialRepository Credentials { get; }
    public KeySetRotationProofs Proofs { get; }
    public PublicKeySetRegistrar Registrar { get; }
    public PasskeyCeremony Ceremony { get; }
    public PasskeyKeySetRotationProof Proof { get; }
    public KeySetHandover Handover { get; }
    public PasskeyInventory Inventory { get; }

    /// <summary>Signs up with the authenticator: its passkey becomes the handle's key set.</summary>
    public string SignUp(SyntheticAuthenticator authenticator, string handle = Handle)
    {
        PasskeyCreationOptions creation = Ceremony.BeginRegistration(handle, "Jane Doe");
        PasskeyRegistrationResult result = Ceremony.CompleteRegistration(handle, authenticator.Register(Base64UrlEncoder.Default.Decode(creation.Challenge)));
        if (!result.Success || !result.KeySetRegistered)
        {
            throw new InvalidOperationException("sign-up did not register the key set: " + result.Failure);
        }
        return result.CredentialId!;
    }

    /// <summary>Adds another passkey through the authenticated path.</summary>
    public string Add(SyntheticAuthenticator authenticator, string handle = Handle)
    {
        PasskeyCreationOptions creation = Ceremony.BeginAdditionalRegistration(handle, "Jane Doe");
        PasskeyRegistrationResult result = Ceremony.CompleteAdditionalRegistration(handle, authenticator.Register(Base64UrlEncoder.Default.Decode(creation.Challenge)));
        if (!result.Success)
        {
            throw new InvalidOperationException("adding a passkey failed: " + result.Failure);
        }
        return result.CredentialId!;
    }

    /// <summary>The assertion JSON the authenticator makes over a challenge, with its counter advanced.</summary>
    public static byte[] AssertionJson(SyntheticAuthenticator authenticator, byte[] challenge)
    {
        authenticator.SignCount++;
        return Encoding.UTF8.GetBytes(PasskeyJson.Serialize(authenticator.Assert(challenge)));
    }

    /// <summary>The assertion JSON the authenticator makes over a begun handover's challenge.</summary>
    public static byte[] AssertionJson(SyntheticAuthenticator authenticator, KeySetHandoverStart start)
    {
        return AssertionJson(authenticator, Base64UrlEncoder.Default.Decode(start.Options!.Challenge));
    }

    /// <summary>Whether the handle's registered key set is exactly this authenticator's key.</summary>
    public bool KeySetIs(SyntheticAuthenticator authenticator, string handle = Handle)
    {
        PublicKeySetData? keySet = Registrar.Resolve(handle);
        PasskeyCredentialData holder = new PasskeyCredentialData { PersonHandle = handle, PublicKeyPem = authenticator.PublicKeyPem };
        return PasskeyKeySet.IsHeldBy(keySet, holder);
    }

    /// <summary>Whether registering this authenticator's key under another handle is refused as revoked material.</summary>
    public bool KeyIsBlocklisted(SyntheticAuthenticator authenticator)
    {
        PublicKeySetData elsewhere = PasskeyKeySet.From("someone-else-" + Guid.NewGuid().ToString("N"), authenticator.Algorithm, authenticator.PublicKeyPem);
        try
        {
            Registrar.Register(elsewhere);
            return false;
        }
        catch (RevokedKeyMaterialException)
        {
            return true;
        }
    }

    /// <summary>A fresh encrypted object store under <c>./.bam/tests/{testName}</c>.</summary>
    public static ObjectDataRepository CreateObjectDataRepository(string testName)
    {
        string rootPath = $"./.bam/tests/{testName}";
        if (Directory.Exists(rootPath))
        {
            Directory.Delete(rootPath, true);
        }
        AesKey aesKey = new AesKey();
        ICompositeKeyCalculator compositeKeyCalculator = new CompositeKeyCalculator();
        IObjectDataIdentityCalculator identityCalculator = new ObjectDataIdentityCalculator();
        IObjectDataLocatorFactory locatorFactory = new ObjectDataLocatorFactory(identityCalculator);
        IObjectEncoderDecoder encoderDecoder = new JsonObjectDataEncoder();
        IObjectDataFactory factory = new ObjectDataFactory(locatorFactory, encoderDecoder);
        IRootStorageHolder rootStorage = new RootStorageHolder(rootPath);
        IObjectDataStorageManager storageManager = new EncryptedFsObjectDataStorageManager(rootStorage, factory, new AesEncryptor(aesKey), new AesDecryptor(aesKey));
        IObjectDataWriter writer = new ObjectDataWriter(factory, storageManager);
        IObjectDataReader reader = new ObjectDataReader(storageManager);
        IObjectDataIndexer indexer = new ObjectDataIndexer(storageManager, compositeKeyCalculator);
        IObjectDataSearchIndexer searchIndexer = new ObjectDataSearchIndexer(storageManager, indexer);
        IObjectDataSearcher searcher = new ObjectDataSearcher(searchIndexer, reader, indexer);
        IObjectDataDeleter deleter = new ObjectDataDeleter(factory, storageManager, compositeKeyCalculator);
        IObjectDataArchiver archiver = new ObjectDataArchiver(factory, storageManager, compositeKeyCalculator);
        return new ObjectDataRepository(factory, writer, indexer, deleter, archiver, reader, searcher, searchIndexer, compositeKeyCalculator);
    }
}
