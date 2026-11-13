// bam.useraccounts.web passkey module.
//
// Runs the WebAuthn ceremonies for the account pages against the JSON endpoints under /account,
// and handles the data-account-action elements inside the account shell. The shell hands it the
// host's wording in a data-account-config attribute. Each exported function can also be called
// directly.
//
// A module is evaluated once per document, and Blazor's enhanced navigation swaps pages in
// without reloading it. So nothing here binds to page elements: one set of listeners on the
// document handles whatever page is showing.
//
// The module may load on every page of a host, next to content the host didn't write. So it
// takes nothing that decides where a request goes or where the browser navigates from the page:
// the prefix and the header are constants, an element counts only inside the shell the account
// pages render, and every redirect target must be a local path.

export const version = "2";

const prefix = "/account";
const header = "X-Bam-Account";
const shellSelector = "[data-account-config]";
const defaults = { availability: false, messages: {} };

// The shell whose action is running, for its wording. Null outside an action.
let activeShell = null;

function settingsOf(shell) {
    if (!shell) {
        return defaults;
    }
    try {
        const parsed = JSON.parse(shell.dataset.accountConfig);
        return {
            availability: parsed.availability === true,
            messages: parsed.messages && typeof parsed.messages === "object" ? parsed.messages : {}
        };
    } catch {
        return defaults;
    }
}

/** Whether a URL is a path on this site, by the same rule as the server's AccountRoutes.IsLocalPath. */
export function isLocalPath(url) {
    if (typeof url !== "string" || url.length === 0 || url[0] !== "/") {
        return false;
    }
    if (url.length > 1 && (url[1] === "/" || url[1] === "\\")) {
        return false;
    }
    return !/[\u0000-\u001f\u007f-\u009f\\]/.test(url);
}

function go(url, fallback) {
    location.assign(isLocalPath(url) ? url : fallback);
}

/** An endpoint refusal: a coarse code and the host's message for it. */
export class AccountError extends Error {
    constructor(code, message, status) {
        super(message);
        this.name = "AccountError";
        this.code = code;
        this.status = status;
    }
}

function message(key, fallback) {
    const text = settingsOf(activeShell).messages[key];
    return typeof text === "string" && text ? text : fallback || "";
}

export function bytesToBase64Url(buffer) {
    const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    let binary = "";
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlToBytes(text) {
    const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index++) {
        bytes[index] = binary.charCodeAt(index);
    }
    return bytes.buffer;
}

function descriptors(list) {
    return (list || []).map(item => Object.assign({}, item, { id: base64UrlToBytes(item.id) }));
}

function creationOptions(json) {
    if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function") {
        return PublicKeyCredential.parseCreationOptionsFromJSON(json);
    }
    return Object.assign({}, json, {
        challenge: base64UrlToBytes(json.challenge),
        user: Object.assign({}, json.user, { id: base64UrlToBytes(json.user.id) }),
        excludeCredentials: descriptors(json.excludeCredentials)
    });
}

function requestOptions(json) {
    if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function") {
        return PublicKeyCredential.parseRequestOptionsFromJSON(json);
    }
    return Object.assign({}, json, {
        challenge: base64UrlToBytes(json.challenge),
        allowCredentials: descriptors(json.allowCredentials)
    });
}

function credentialToJson(credential) {
    if (typeof credential.toJSON === "function") {
        return credential.toJSON();
    }
    const response = credential.response;
    const json = { id: credential.id, rawId: bytesToBase64Url(credential.rawId), type: credential.type, response: { clientDataJSON: bytesToBase64Url(response.clientDataJSON) } };
    if (response.attestationObject) {
        json.response.attestationObject = bytesToBase64Url(response.attestationObject);
        json.response.transports = typeof response.getTransports === "function" ? response.getTransports() : [];
    } else {
        json.response.authenticatorData = bytesToBase64Url(response.authenticatorData);
        json.response.signature = bytesToBase64Url(response.signature);
        if (response.userHandle && response.userHandle.byteLength > 0) {
            json.response.userHandle = bytesToBase64Url(response.userHandle);
        }
    }
    return json;
}

async function call(method, path, body) {
    const headers = { Accept: "application/json" };
    headers[header] = "1";
    const init = { method, headers, credentials: "same-origin" };
    if (body !== undefined) {
        headers["Content-Type"] = "application/json";
        init.body = JSON.stringify(body);
    }
    const response = await fetch(prefix + path, init);
    const isJson = (response.headers.get("Content-Type") || "").startsWith("application/json");
    const payload = isJson ? await response.json() : null;
    if (response.ok) {
        return payload;
    }
    if (response.status === 429) {
        throw new AccountError("RateLimited", message("rateLimited", "Too many attempts."), 429);
    }
    throw new AccountError(payload && payload.error || "Failed", payload && payload.message || message("actionFailed", "That didn't work."), response.status);
}

function requireSupport() {
    if (!window.PublicKeyCredential || !navigator.credentials) {
        throw new AccountError("Unsupported", message("unsupported", "This browser doesn't support passkeys."), 0);
    }
}

// The browser reports a dismissed or timed-out prompt as NotAllowedError (or AbortError).
async function prompt(run) {
    try {
        const credential = await run();
        if (!credential) {
            throw new AccountError("Cancelled", message("cancelled", "The passkey prompt was dismissed."), 0);
        }
        return credential;
    } catch (error) {
        if (error instanceof AccountError) {
            throw error;
        }
        if (error && (error.name === "NotAllowedError" || error.name === "AbortError")) {
            throw new AccountError("Cancelled", message("cancelled", "The passkey prompt was dismissed."), 0);
        }
        throw new AccountError("PasskeyFailed", message("actionFailed", "That didn't work."), 0);
    }
}

/** Signs up: fields are { handle, displayName, email, inviteCode }. Resolves to { handle, displayName, nextUrl, profileCreated }. */
export async function register(fields) {
    requireSupport();
    const begun = await call("POST", "/passkey/registration/begin", fields);
    const credential = await prompt(() => navigator.credentials.create({ publicKey: creationOptions(begun.options) }));
    return call("POST", "/passkey/registration/complete", Object.assign({}, fields, { credential: credentialToJson(credential) }));
}

/** Signs in. A blank handle lets the authenticator offer its passkeys. Resolves to { handle, displayName, nextUrl }. */
export async function signIn(handle, returnUrl) {
    requireSupport();
    const begun = await call("POST", "/passkey/assertion/begin", { handle: handle || null });
    const credential = await prompt(() => navigator.credentials.get({ publicKey: requestOptions(begun.options) }));
    return call("POST", "/passkey/assertion/complete", { ceremonyId: begun.ceremonyId, credential: credentialToJson(credential), returnUrl: returnUrl || null });
}

/** Adds a passkey to the signed-in account. Resolves to { credentialId }. */
export async function addPasskey(name) {
    requireSupport();
    const begun = await call("POST", "/passkey/additional/begin", {});
    const credential = await prompt(() => navigator.credentials.create({ publicKey: creationOptions(begun.options) }));
    return call("POST", "/passkey/additional/complete", { credential: credentialToJson(credential), name: name || null });
}

/** Renames one of the signed-in person's passkeys. */
export function rename(credentialId, name) {
    return call("POST", "/passkeys/" + encodeURIComponent(credentialId) + "/name", { name: name || null });
}

/**
 * Removes one of the signed-in person's passkeys. Resolves to { signedOut, nextUrl }. A passkey
 * that holds the account's key set is refused with code KeySetHandoverRequired: hand it over with
 * handOver, or pass keepKeySet to remove it and leave the key set where it is.
 */
export function remove(credentialId, keepKeySet) {
    return call("DELETE", "/passkeys/" + encodeURIComponent(credentialId) + (keepKeySet ? "?keySet=keep" : ""));
}

/**
 * Moves the key set from the passkey being removed to another of the person's passkeys (the one
 * this session signed in with unless heir is given), then removes it. The browser asks for the
 * passkey being removed. Resolves to { signedOut, nextUrl }.
 */
export async function handOver(credentialId, heir) {
    requireSupport();
    const path = "/passkeys/" + encodeURIComponent(credentialId) + "/handover";
    const begun = await call("POST", path + "/begin", { heir: heir || null });
    const credential = await prompt(() => navigator.credentials.get({ publicKey: requestOptions(begun.options) }));
    return call("POST", path + "/complete", { handoverId: begun.handoverId, credential: credentialToJson(credential) });
}

// The other passkeys listed in this shell, as heir candidates. The server checks the heir is the
// person's own registered passkey, so a listed id can't move the key set anywhere else.
function otherPasskeys(shell, credentialId) {
    const ids = [];
    for (const element of shell.querySelectorAll("[data-account-credential]")) {
        const id = element.dataset.accountCredential;
        if (element.dataset.accountAction === "remove" && id && id !== credentialId && !ids.includes(id)) {
            ids.push(id);
        }
    }
    return ids;
}

// Removes a passkey, asking to move the key set first when it holds it.
async function removeOrHandOver(credentialId, shell) {
    try {
        return await remove(credentialId);
    } catch (error) {
        if (!(error instanceof AccountError) || error.code !== "KeySetHandoverRequired") {
            throw error;
        }
    }
    if (window.confirm(message("keySetHandoverPrompt", "This passkey holds your account's key. Move it first?"))) {
        try {
            try {
                return await handOver(credentialId);
            } catch (error) {
                // This session signed in with the passkey being removed: hand the key set to another one.
                const heir = error instanceof AccountError && error.code === "InvalidHeir" ? otherPasskeys(shell, credentialId)[0] : undefined;
                if (!heir) {
                    throw error;
                }
                return await handOver(credentialId, heir);
            }
        } catch (error) {
            // The key can't be moved from here (no other passkey to take it, or this host can't
            // move it): fall through to removing it without the move. Anything else is a failure.
            if (!(error instanceof AccountError) || (error.code !== "InvalidHeir" && error.code !== "RotationUnavailable")) {
                throw error;
            }
        }
    }
    if (!window.confirm(message("keySetKeepConfirmation", "Remove this passkey anyway?"))) {
        return null;
    }
    return remove(credentialId, true);
}

/** Ends the session. Resolves to { signedOut, nextUrl }. */
export function signOut() {
    return call("POST", "/signout", {});
}

/** Finishes a profile that wasn't saved at sign-up: fields are { displayName, email }. */
export function completeProfile(fields) {
    return call("POST", "/profile", { displayName: fields.displayName || null, email: fields.email || null });
}

/** Asks whether a handle can be signed up with. Resolves to { handle, available, reason }. */
export function checkHandle(handle) {
    return call("GET", "/handle/" + encodeURIComponent(handle) + "/availability");
}

// ---- page binding ---------------------------------------------------------------------------
//
// Everything below acts only on elements inside an account shell, and reads that shell's
// settings, never the first shell or form id in the document.

function shellOf(element) {
    return element ? element.closest(shellSelector) : null;
}

function status(shell, text, failed) {
    const element = shell.querySelector("[data-account-status]");
    if (element) {
        element.textContent = text || "";
        element.classList.toggle("account-status-error", Boolean(failed));
    }
}

function fields(shell, formId) {
    const values = {};
    const form = formId ? document.getElementById(formId) : null;
    if (form && shell.contains(form)) {
        for (const [name, value] of new FormData(form).entries()) {
            values[name] = typeof value === "string" ? value.trim() : value;
        }
    }
    return values;
}

const signedOutUrl = prefix + "/signedout";

const actions = {
    async register(button, shell) {
        const done = await register(fields(shell, button.dataset.accountForm));
        go(done && done.nextUrl, prefix);
    },
    async signin(button, shell) {
        const done = await signIn(fields(shell, button.dataset.accountForm).handle, button.dataset.accountReturn);
        go(done && done.nextUrl, prefix);
    },
    async add(button, shell) {
        await addPasskey(fields(shell, button.dataset.accountForm).name);
        location.reload();
    },
    async rename(button, shell) {
        await rename(button.dataset.accountCredential, fields(shell, button.dataset.accountForm).name);
        location.reload();
    },
    async remove(button, shell) {
        if (!window.confirm(message("removeConfirmation", "Remove this passkey?"))) {
            return;
        }
        const done = await removeOrHandOver(button.dataset.accountCredential, shell);
        if (!done) {
            return;
        }
        if (done.signedOut) {
            go(done.nextUrl, signedOutUrl);
        } else {
            location.reload();
        }
    },
    async profile(button, shell) {
        await completeProfile(fields(shell, button.dataset.accountForm));
        location.reload();
    },
    async signout() {
        const done = await signOut();
        go(done && done.nextUrl, signedOutUrl);
    }
};

const ceremonies = new Set(["register", "signin", "add"]);

// Actions that change a signed-in account. Only the manage page renders them.
const manageActions = new Set(["add", "rename", "remove", "profile"]);

function onAccountPage(path) {
    return path === prefix || path.startsWith(prefix + "/");
}

function onManagePage(path) {
    return path === prefix || path === prefix + "/";
}

// Real shells are rendered only by the account pages, one per page. An action elsewhere, an
// account-changing action off the manage page, or a page with a second shell (markup injected
// next to the real one) is refused rather than guessed at.
function allowed(name) {
    const path = location.pathname || "";
    if (!onAccountPage(path) || (manageActions.has(name) && !onManagePage(path))) {
        return false;
    }
    return document.querySelectorAll(shellSelector).length === 1;
}

async function run(button) {
    const shell = shellOf(button);
    const name = button.dataset.accountAction;
    const action = Object.prototype.hasOwnProperty.call(actions, name) ? actions[name] : null;
    if (!shell || !action || button.disabled || !allowed(name)) {
        return;
    }
    button.disabled = true;
    activeShell = shell;
    status(shell, ceremonies.has(button.dataset.accountAction) ? message("working") : "", false);
    try {
        await action(button, shell);
    } catch (error) {
        status(shell, error instanceof AccountError ? error.message : message("actionFailed", "That didn't work."), true);
    } finally {
        button.disabled = false;
        activeShell = null;
    }
}

async function checkAvailability(input) {
    const shell = shellOf(input);
    const hint = shell ? shell.querySelector("[data-account-handle-hint]") : null;
    if (!hint || !allowed("check") || !settingsOf(shell).availability) {
        return;
    }
    if (hint.dataset.accountHelp === undefined) {
        hint.dataset.accountHelp = hint.textContent;
    }
    const help = hint.dataset.accountHelp;
    const handle = input.value.trim().toLowerCase();
    if (!handle) {
        hint.textContent = help;
        return;
    }
    const messages = settingsOf(shell).messages;
    try {
        const answer = await checkHandle(handle);
        const key = answer.available ? "handleAvailable" : answer.reason === "Taken" ? "handleTaken" : answer.reason === "Invalid" ? "handleInvalid" : null;
        hint.textContent = key && typeof messages[key] === "string" ? messages[key] : help;
    } catch {
        hint.textContent = help;
    }
}

function targetOf(event, selector) {
    const element = event.target instanceof Element ? event.target.closest(selector) : null;
    return element && shellOf(element) ? element : null;
}

document.addEventListener("click", event => {
    const button = targetOf(event, "[data-account-action]");
    if (button) {
        event.preventDefault();
        run(button);
    }
});

// Enter in a field runs the form's first action instead of submitting the form.
document.addEventListener("submit", event => {
    const form = targetOf(event, ".account-form, .account-passkey-form");
    if (form) {
        event.preventDefault();
        const button = form.querySelector("[data-account-action]");
        if (button) {
            run(button);
        }
    }
});

document.addEventListener("change", event => {
    const input = targetOf(event, "[data-account-handle]");
    if (input) {
        checkAvailability(input);
    }
});
