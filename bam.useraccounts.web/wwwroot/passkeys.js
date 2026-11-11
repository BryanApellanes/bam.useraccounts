// bam.useraccounts.web passkey module.
//
// Runs the WebAuthn ceremonies for the account pages against the JSON endpoints under the
// account prefix, and binds itself to every element carrying data-account-action. The page
// shell hands it its settings (endpoint prefix, request header, the host's wording) in a
// data-account-config attribute. Each exported function can also be called directly.

export const version = "1";

const shell = document.querySelector("[data-account-config]");
const config = Object.assign(
    { prefix: "/account", header: "X-Bam-Account", availability: false, messages: {} },
    shell ? JSON.parse(shell.dataset.accountConfig) : {});

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
    return config.messages[key] || fallback || "";
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
    headers[config.header] = "1";
    const init = { method, headers, credentials: "same-origin" };
    if (body !== undefined) {
        headers["Content-Type"] = "application/json";
        init.body = JSON.stringify(body);
    }
    const response = await fetch(config.prefix + path, init);
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

/** Removes one of the signed-in person's passkeys. Resolves to { signedOut, nextUrl }. */
export function remove(credentialId) {
    return call("DELETE", "/passkeys/" + encodeURIComponent(credentialId));
}

/** Ends the session. Resolves to { signedOut, nextUrl }. */
export function signOut() {
    return call("POST", "/signout", {});
}

/** Asks whether a handle can be signed up with. Resolves to { handle, available, reason }. */
export function checkHandle(handle) {
    return call("GET", "/handle/" + encodeURIComponent(handle) + "/availability");
}

// ---- page binding ---------------------------------------------------------------------------

function status(text, failed) {
    const element = document.querySelector("[data-account-status]");
    if (element) {
        element.textContent = text || "";
        element.classList.toggle("account-status-error", Boolean(failed));
    }
}

function fields(formId) {
    const values = {};
    const form = formId ? document.getElementById(formId) : null;
    if (form) {
        for (const [name, value] of new FormData(form).entries()) {
            values[name] = typeof value === "string" ? value.trim() : value;
        }
    }
    return values;
}

const actions = {
    async register(button) {
        const done = await register(fields(button.dataset.accountForm));
        location.assign(done.nextUrl);
    },
    async signin(button) {
        const done = await signIn(fields(button.dataset.accountForm).handle, button.dataset.accountReturn);
        location.assign(done.nextUrl);
    },
    async add(button) {
        await addPasskey(fields(button.dataset.accountForm).name);
        location.reload();
    },
    async rename(button) {
        await rename(button.dataset.accountCredential, fields(button.dataset.accountForm).name);
        location.reload();
    },
    async remove(button) {
        if (!window.confirm(message("removeConfirmation", "Remove this passkey?"))) {
            return;
        }
        const done = await remove(button.dataset.accountCredential);
        if (done && done.signedOut && done.nextUrl) {
            location.assign(done.nextUrl);
        } else {
            location.reload();
        }
    },
    async signout() {
        const done = await signOut();
        location.assign(done && done.nextUrl || config.prefix + "/signedout");
    }
};

const ceremonies = new Set(["register", "signin", "add"]);

async function run(button) {
    const action = actions[button.dataset.accountAction];
    if (!action || button.disabled) {
        return;
    }
    button.disabled = true;
    status(ceremonies.has(button.dataset.accountAction) ? message("working") : "", false);
    try {
        await action(button);
    } catch (error) {
        status(error instanceof AccountError ? error.message : message("actionFailed", "That didn't work."), true);
    } finally {
        button.disabled = false;
    }
}

function bindAvailability(input) {
    const hint = document.querySelector("[data-account-handle-hint]");
    if (!hint || !config.availability) {
        return;
    }
    const help = hint.textContent;
    input.addEventListener("change", async () => {
        const handle = input.value.trim().toLowerCase();
        if (!handle) {
            hint.textContent = help;
            return;
        }
        try {
            const answer = await checkHandle(handle);
            const key = answer.available ? "handleAvailable" : answer.reason === "Taken" ? "handleTaken" : answer.reason === "Invalid" ? "handleInvalid" : null;
            hint.textContent = key ? message(key, help) : help;
        } catch {
            hint.textContent = help;
        }
    });
}

function bind() {
    for (const button of document.querySelectorAll("[data-account-action]")) {
        if (!button.dataset.accountBound) {
            button.dataset.accountBound = "1";
            button.addEventListener("click", () => run(button));
        }
    }
    // Enter in a field runs the form's first action instead of submitting the form.
    for (const form of document.querySelectorAll(".account-form, .account-passkey-form")) {
        if (!form.dataset.accountBound) {
            form.dataset.accountBound = "1";
            form.addEventListener("submit", event => {
                event.preventDefault();
                const button = form.querySelector("[data-account-action]");
                if (button) {
                    run(button);
                }
            });
        }
    }
    for (const input of document.querySelectorAll("[data-account-handle]")) {
        if (!input.dataset.accountBound) {
            input.dataset.accountBound = "1";
            bindAvailability(input);
        }
    }
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bind);
} else {
    bind();
}
