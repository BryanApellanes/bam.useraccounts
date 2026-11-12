// Checks that passkeys.js takes nothing from the page that decides where a request goes or where
// the browser navigates. Runs the module against a stub DOM.
// Usage: node passkeys.check.mjs <path to passkeys.js>. Exits 0 when every check passes.
import { readFileSync } from "node:fs";

const source = readFileSync(process.argv[2], "utf8");

class Element {
    constructor({ dataset = {}, classes = [], id = null, parent = null } = {}) {
        this.dataset = dataset;
        this.classes = new Set(classes);
        this.id = id;
        this.parent = parent;
        this.disabled = false;
        this.textContent = "";
        this.children = [];
        if (parent) {
            parent.children.push(this);
        }
        this.classList = { toggle: () => {} };
    }

    matches(selector) {
        return selector.split(",").map(part => part.trim()).some(part => {
            if (part.startsWith(".")) {
                return this.classes.has(part.slice(1));
            }
            const attribute = /^\[data-([a-z-]+)\]$/.exec(part);
            if (!attribute) {
                return false;
            }
            const key = attribute[1].replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
            return this.dataset[key] !== undefined;
        });
    }

    closest(selector) {
        for (let node = this; node; node = node.parent) {
            if (node.matches(selector)) {
                return node;
            }
        }
        return null;
    }

    contains(other) {
        for (let node = other; node; node = node.parent) {
            if (node === this) {
                return true;
            }
        }
        return false;
    }

    querySelector(selector) {
        for (const child of this.children) {
            if (child.matches(selector)) {
                return child;
            }
            const found = child.querySelector(selector);
            if (found) {
                return found;
            }
        }
        return null;
    }
}

let root = new Element();
const listeners = {};
let fetched = [];
let assigned = [];
let confirmed = 0;
let nextReply = {};

function all(node, selector, found) {
    for (const child of node.children) {
        if (child.matches(selector)) {
            found.push(child);
        }
        all(child, selector, found);
    }
    return found;
}

globalThis.Element = Element;
globalThis.document = {
    addEventListener: (type, listener) => { listeners[type] = listener; },
    querySelector: selector => root.querySelector(selector),
    querySelectorAll: selector => all(root, selector, []),
    getElementById: id => {
        const search = node => node.id === id ? node : node.children.map(search).find(Boolean) || null;
        return search(root);
    }
};
globalThis.window = { confirm: () => { confirmed++; return true; }, PublicKeyCredential: {} };
globalThis.PublicKeyCredential = { parseCreationOptionsFromJSON: json => json, parseRequestOptionsFromJSON: json => json };
// Node has its own navigator, read-only; replace it.
Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { credentials: { create: async () => ({ toJSON: () => ({ id: "new-cred" }) }), get: async () => ({ toJSON: () => ({ id: "cred-1" }) }) } }
});
// A form's entries are the values the test gave it.
globalThis.FormData = class { constructor(form) { this.values = form.values || []; } entries() { return this.values; } };
globalThis.fetch = async (url, init) => {
    fetched.push({ url, method: init.method, header: init.headers["X-Bam-Account"], body: init.body ? JSON.parse(init.body) : null });
    return { ok: true, status: 200, headers: { get: () => "application/json" }, json: async () => nextReply };
};
globalThis.location = { pathname: "/account", assign: url => assigned.push(url), reload: () => assigned.push("(reload)") };

const module = await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));

const failures = [];
function expect(name, condition, detail) {
    if (!condition) {
        failures.push(`${name}: ${JSON.stringify(detail)}`);
    }
}

// A fresh document at a path.
function at(path) {
    root = new Element();
    location.pathname = path;
}

async function click(element, reply) {
    fetched = [];
    assigned = [];
    confirmed = 0;
    nextReply = reply;
    listeners.click({ target: element, preventDefault() {} });
    await new Promise(resolve => setTimeout(resolve, 20));
}

function shell() {
    return new Element({ dataset: { accountConfig: JSON.stringify({ availability: true, messages: {} }) }, classes: ["account-shell"], parent: root });
}

function gadget(action, extra = {}) {
    const config = JSON.stringify({ prefix: "https://evil.example", header: "X-Other", messages: { removeConfirmation: "Click OK to continue" } });
    return new Element({ dataset: Object.assign({ accountAction: action, accountConfig: config }, extra), parent: root });
}

// Injected markup that configures itself, alone on an account page: the prefix it names is
// ignored, and the javascript: target the reply names is never followed.
at("/account/signin");
await click(gadget("signout"), { signedOut: true, nextUrl: "javascript:alert(document.domain)" });
expect("the prefix comes from the module", fetched.length === 1 && fetched[0].url === "/account/signout" && fetched[0].header === "1", fetched);
expect("a javascript: target is not followed", assigned.length === 1 && assigned[0] === "/account/signedout", assigned);

// The same gadget on a host page, where no real shell renders, does nothing.
at("/blog/post-1");
await click(gadget("signout"), { signedOut: true, nextUrl: "/account/signedout" });
expect("nothing runs off the account pages", fetched.length === 0 && assigned.length === 0, { fetched, assigned });

// A self-configured remove gadget on an account page other than manage: no request, no confirm.
at("/account/signin");
await click(gadget("remove", { accountCredential: "cred-1" }), { signedOut: true, nextUrl: "/account/signedout" });
expect("an account-changing action off the manage page is refused", fetched.length === 0 && confirmed === 0, { fetched, confirmed });

// The same gadget next to the real shell on the manage page: two shells, so nothing runs.
at("/account");
shell();
await click(gadget("remove", { accountCredential: "cred-1" }), { signedOut: true, nextUrl: "/account/signedout" });
expect("a second shell disables the module", fetched.length === 0 && confirmed === 0, { fetched, confirmed });

// An action element outside any account shell does nothing.
at("/account");
shell();
const stray = new Element({ dataset: { accountAction: "signout" }, parent: root });
await click(stray, { signedOut: true, nextUrl: "/account/signedout" });
expect("an element outside the shell is ignored", fetched.length === 0 && assigned.length === 0, { fetched, assigned });

// Inside the one real shell, a local target is followed and anything else falls back.
at("/account");
const page = shell();
const signOut = new Element({ dataset: { accountAction: "signout" }, parent: page });
await click(signOut, { signedOut: true, nextUrl: "/goodbye" });
expect("a local target is followed", assigned[0] === "/goodbye", assigned);
for (const target of ["//evil.example", "/\\evil.example", "https://evil.example", "/a\\b", "/a\u0000b", "", null]) {
    await click(signOut, { signedOut: true, nextUrl: target });
    expect(`target ${JSON.stringify(target)} falls back`, assigned[0] === "/account/signedout", assigned);
}

// The real shell's remove on the manage page still works, with its confirm.
const removeButton = new Element({ dataset: { accountAction: "remove", accountCredential: "cred-1" }, parent: page });
await click(removeButton, { signedOut: true, nextUrl: "https://evil.example" });
expect("the manage page's remove runs and falls back to the signed-out page",
    confirmed === 1 && fetched.length === 1 && fetched[0].url === "/account/passkeys/cred-1" && fetched[0].method === "DELETE" && assigned[0] === "/account/signedout", { confirmed, fetched, assigned });
location.pathname = "/account/";
await click(removeButton, { signedOut: false });
expect("the manage page with a trailing slash counts", fetched.length === 1 && assigned[0] === "(reload)", { fetched, assigned });
location.pathname = "/account";

// A form the action names is read when it sits in the same shell, and not otherwise.
const profileForm = new Element({ id: "account-profile", parent: page });
profileForm.values = [["displayName", " Jane Doe "], ["email", "jane@example.com"]];
await click(new Element({ dataset: { accountAction: "profile", accountForm: "account-profile" }, parent: page }), {});
expect("the profile form's values are sent, trimmed",
    fetched.length === 1 && fetched[0].url === "/account/profile" && fetched[0].body.displayName === "Jane Doe" && fetched[0].body.email === "jane@example.com", fetched);

at("/account");
const manage = shell();
const foreignForm = new Element({ id: "account-profile", parent: root });
foreignForm.values = [["displayName", "Mallory"]];
await click(new Element({ dataset: { accountAction: "profile", accountForm: "account-profile" }, parent: manage }), {});
expect("a form outside the shell is not read", fetched.length === 1 && fetched[0].url === "/account/profile" && fetched[0].body.displayName === null, fetched);

// Sign-up and sign-in send what the person typed.
at("/account/signup");
const signUpPage = shell();
const signUpForm = new Element({ id: "account-signup", parent: signUpPage });
signUpForm.values = [["handle", "jane-doe"], ["displayName", "Jane Doe"], ["email", "jane@example.com"]];
await click(new Element({ dataset: { accountAction: "register", accountForm: "account-signup" }, parent: signUpPage }), { options: {}, nextUrl: "/account" });
expect("sign-up begins with the form's values",
    fetched.length === 2 && fetched[0].url === "/account/passkey/registration/begin" && fetched[0].body.handle === "jane-doe" && fetched[0].body.displayName === "Jane Doe" && fetched[0].body.email === "jane@example.com", fetched);
expect("and completes with them and the credential",
    fetched.length === 2 && fetched[1].url === "/account/passkey/registration/complete" && fetched[1].body.handle === "jane-doe" && fetched[1].body.credential.id === "new-cred", fetched);

at("/account/signin");
const signInPage = shell();
const signInForm = new Element({ id: "account-signin", parent: signInPage });
signInForm.values = [["handle", "jane-doe"]];
await click(new Element({ dataset: { accountAction: "signin", accountForm: "account-signin", accountReturn: "/orders" }, parent: signInPage }), { options: {}, ceremonyId: "c-1", nextUrl: "/orders" });
expect("sign-in begins with the typed handle", fetched.length === 2 && fetched[0].url === "/account/passkey/assertion/begin" && fetched[0].body.handle === "jane-doe", fetched);
expect("and completes with the ceremony and the return URL",
    fetched.length === 2 && fetched[1].body.ceremonyId === "c-1" && fetched[1].body.returnUrl === "/orders" && assigned[0] === "/orders", { fetched, assigned });

expect("the module exports isLocalPath", typeof module.isLocalPath === "function", Object.keys(module));
for (const [url, local] of typeof module.isLocalPath !== "function" ? [] : [["/account", true], ["/", true], ["//x", false], ["/\\x", false], ["http://x", false], ["/a\tb", false], ["/a\u0085b", false]]) {
    expect(`isLocalPath(${JSON.stringify(url)})`, module.isLocalPath(url) === local, url);
}

if (failures.length > 0) {
    console.log("FAILED");
    for (const failure of failures) {
        console.log(failure);
    }
    process.exit(1);
}
console.log("passkeys.js checks passed");
