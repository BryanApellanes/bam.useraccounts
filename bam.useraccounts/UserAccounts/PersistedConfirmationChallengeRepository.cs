using Bam.Data;
using Bam.Data.Repositories;

namespace Bam.UserAccounts;

/// <summary>
/// Durable <see cref="IConfirmationChallengeRepository"/> backed by an <see cref="IRepository"/>,
/// so pending challenges survive a process restart.  Maintains the one-pending-challenge-per-handle
/// invariant by deleting any prior records for a handle on <see cref="Save"/>.
/// <para>
/// Hardening (BryanApellanes/bam.useraccounts#3): all store lookups use keyed query overloads
/// (<see cref="IRepository.Query{T}(Dictionary{string, object})"/>) rather than predicate scans, so
/// backends that translate keyed queries (e.g. <c>DaoRepository</c>) never retrieve the full
/// challenge table; expired challenges are reaped opportunistically (throttled by
/// <see cref="ReapInterval"/>) so abandoned challenges do not accumulate; and a bounded in-process
/// write-through cache (capped at <see cref="MaxCachedChallenges"/>) serves handle lookups without
/// a store query, with the durable store remaining authoritative.  Note:
/// <c>ObjectDataRepository</c> currently services keyed queries by full scan — tracked as
/// BryanApellanes/bam.data.objects#2.  The cache is a plain bounded dictionary rather than
/// <c>Bam.Caching</c> because that submodule is not currently fit for keyed write-through caching —
/// tracked as BryanApellanes/bam.caching#1; migrate when it lands.
/// </para>
/// <para>
/// Single-use enforcement (<see cref="Take"/>) claims the pending record by presenting it for
/// delete and honoring the store's report of whether a row was actually removed: within one
/// process the claim is serialized under a process-local lock, and a claim whose delete reports
/// no row removed yields null.  Because <see cref="IRepository"/> deletes are fetch-then-delete
/// rather than atomic, two processes sharing the same backing store can still race a concurrent
/// Take in the window between fetch and delete.  Fully excluding a cross-process double-take
/// requires an atomic delete-returning storage operation, tracked as
/// BryanApellanes/threeheadz-tracker#24.  Register as a singleton (see
/// <c>UserAccountsServiceRegistration</c>) so custody state is shared within the process.
/// </para>
/// <para>
/// Consumers exposing unauthenticated challenge creation should additionally rate-limit
/// <c>CreateChallenge</c> at their boundary: reaping bounds retained rows to the unexpired
/// window, but cannot bound the rate of row creation itself.
/// </para>
/// </summary>
public class PersistedConfirmationChallengeRepository : IConfirmationChallengeRepository
{
    /// <summary>
    /// The default value of <see cref="MaxCachedChallenges"/>.
    /// </summary>
    public const int DefaultMaxCachedChallenges = 10000;

    private readonly IRepository _repository;
    private readonly Dictionary<string, ConfirmationChallengeData> _pendingByHandle = new();
    private readonly object _lock = new();
    private DateTime _lastReapedUtc = DateTime.MinValue;

    /// <summary>
    /// Initializes a new instance of the <see cref="PersistedConfirmationChallengeRepository"/>
    /// class over the specified backing repository, registering
    /// <see cref="ConfirmationChallengeData"/> as a storable type.
    /// </summary>
    /// <param name="repository">The durable store pending challenges are persisted to.</param>
    public PersistedConfirmationChallengeRepository(IRepository repository)
    {
        _repository = repository;
        _repository.AddType<ConfirmationChallengeData>();
    }

    /// <summary>
    /// Gets or sets the minimum interval between opportunistic expired-challenge reaps.  Each
    /// <see cref="Save"/> or <see cref="Take"/> triggers a reap at most this often; set to
    /// <see cref="TimeSpan.Zero"/> to reap on every operation (useful in tests).  Defaults to
    /// one minute.
    /// </summary>
    public TimeSpan ReapInterval { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Gets or sets the upper bound on cached pending challenges.  When the cache is full, new
    /// handles are simply not cached (their lookups fall through to a keyed store query) until
    /// reaping or takes free space — bounding in-process memory growth under attacker-driven
    /// challenge creation without an eviction scan per operation.  Defaults to
    /// <see cref="DefaultMaxCachedChallenges"/>.
    /// </summary>
    public int MaxCachedChallenges { get; set; } = DefaultMaxCachedChallenges;

    /// <summary>
    /// Stores the specified challenge as the pending challenge for its person handle, replacing
    /// any previously pending challenge for that handle, and caches it write-through for
    /// subsequent handle lookups.  Also opportunistically reaps expired challenges (throttled by
    /// <see cref="ReapInterval"/>).
    /// </summary>
    /// <param name="challenge">The challenge to store.</param>
    public void Save(ConfirmationChallenge challenge)
    {
        lock (_lock)
        {
            ReapExpired();
            DeletePending(challenge.PersonHandle);
            ConfirmationChallengeData data = new ConfirmationChallengeData
            {
                PersonHandle = challenge.PersonHandle,
                NonceBase64 = Convert.ToBase64String(challenge.ChallengeBytes),
                ExpiresUtc = challenge.ExpiresUtc
            };
            ConfirmationChallengeData created = _repository.Create(data);
            CachePending(created ?? data);
        }
    }

    /// <summary>
    /// Retrieves AND removes the pending challenge for the specified person handle, returning
    /// null when no challenge is pending or when the store reports the record was already
    /// removed (e.g. taken by another process).  The in-process cache may satisfy the lookup,
    /// but the claim is always made against the durable store: if the store reports a cached
    /// record already gone, the lookup falls back to a keyed store query, so the cache can never
    /// fabricate or suppress a take.
    /// </summary>
    /// <param name="personHandle">The person handle whose pending challenge to take.</param>
    /// <returns>The pending challenge, or null if none exists or the claim was lost.</returns>
    public ConfirmationChallenge? Take(string personHandle)
    {
        lock (_lock)
        {
            ReapExpired();
            bool cacheHit = _pendingByHandle.TryGetValue(personHandle, out ConfirmationChallengeData? pending);
            _pendingByHandle.Remove(personHandle);
            pending ??= QueryPending(personHandle);
            if (pending == null)
            {
                return null;
            }

            if (!_repository.Delete(pending))
            {
                if (!cacheHit)
                {
                    return null;
                }
                // The cached record was stale (its row is already gone); re-read the store,
                // which is authoritative, and claim whatever is genuinely pending.
                pending = QueryPending(personHandle);
                if (pending == null || !_repository.Delete(pending))
                {
                    return null;
                }
            }

            return new ConfirmationChallenge
            {
                PersonHandle = pending.PersonHandle,
                ChallengeBytes = Convert.FromBase64String(pending.NonceBase64),
                ExpiresUtc = pending.ExpiresUtc
            };
        }
    }

    /// <summary>
    /// Deletes every pending record for the specified handle using a keyed query, preserving the
    /// one-pending-challenge-per-handle invariant on <see cref="Save"/>.
    /// </summary>
    /// <param name="personHandle">The person handle whose pending records to delete.</param>
    private void DeletePending(string personHandle)
    {
        _pendingByHandle.Remove(personHandle);
        List<ConfirmationChallengeData> existing = QueryAllPending(personHandle).ToList();
        foreach (ConfirmationChallengeData data in existing)
        {
            _repository.Delete(data);
        }
    }

    /// <summary>
    /// Queries the store for the newest pending record for the specified handle using the keyed
    /// query overload (no full-table predicate scan on translating backends).
    /// </summary>
    /// <param name="personHandle">The person handle to look up.</param>
    /// <returns>The newest pending record, or null when none is pending.</returns>
    private ConfirmationChallengeData? QueryPending(string personHandle)
    {
        return QueryAllPending(personHandle)
            .OrderByDescending(pending => pending.ExpiresUtc)
            .FirstOrDefault();
    }

    /// <summary>
    /// Queries the store for all pending records for the specified handle using the keyed query
    /// overload.
    /// </summary>
    /// <param name="personHandle">The person handle to look up.</param>
    /// <returns>All pending records for the handle.</returns>
    private IEnumerable<ConfirmationChallengeData> QueryAllPending(string personHandle)
    {
        Dictionary<string, object> byHandle = new Dictionary<string, object>
        {
            { nameof(ConfirmationChallengeData.PersonHandle), personHandle }
        };
        return _repository.Query<ConfirmationChallengeData>(byHandle);
    }

    /// <summary>
    /// Reaps expired challenges from the store and the cache, at most once per
    /// <see cref="ReapInterval"/>.  The store reap is a filtered delete
    /// (<c>ExpiresUtc &lt; now</c>) so its cost scales with the number of expired rows, not the
    /// table size, on translating backends.
    /// </summary>
    private void ReapExpired()
    {
        DateTime nowUtc = DateTime.UtcNow;
        if (nowUtc - _lastReapedUtc < ReapInterval)
        {
            return;
        }
        _lastReapedUtc = nowUtc;
        QueryFilter expiredFilter = Query.Where(nameof(ConfirmationChallengeData.ExpiresUtc)) < Query.Value(nowUtc);
        _repository.DeleteWhere<ConfirmationChallengeData>(expiredFilter);

        List<string> expiredHandles = _pendingByHandle
            .Where(cached => cached.Value.ExpiresUtc < nowUtc)
            .Select(cached => cached.Key)
            .ToList();
        foreach (string handle in expiredHandles)
        {
            _pendingByHandle.Remove(handle);
        }
    }

    /// <summary>
    /// Caches the specified created record write-through under its person handle.  When the
    /// cache is at capacity and the handle is not already cached, the record is not cached and
    /// lookups for it fall through to keyed store queries (see <see cref="MaxCachedChallenges"/>).
    /// </summary>
    /// <param name="created">The created pending record, as returned by the store.</param>
    private void CachePending(ConfirmationChallengeData created)
    {
        if (_pendingByHandle.Count >= MaxCachedChallenges && !_pendingByHandle.ContainsKey(created.PersonHandle))
        {
            return;
        }
        _pendingByHandle[created.PersonHandle] = created;
    }
}
