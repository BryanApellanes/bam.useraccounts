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

const root = new Element();
const listeners = {};
let fetched = [];
let assigned = [];
let nextReply = {};

globalThis.Element = Element;
globalThis.document = {
    addEventListener: (type, listener) => { listeners[type] = listener; },
    querySelector: selector => root.querySelector(selector),
    getElementById: id => {
        const search = node => node.id === id ? node : node.children.map(search).find(Boolean) || null;
        return search(root);
    }
};
globalThis.window = { confirm: () => true };
globalThis.fetch = async (url, init) => {
    fetched.push({ url, method: init.method, header: init.headers["X-Bam-Account"], body: init.body ? JSON.parse(init.body) : null });
    return { ok: true, status: 200, headers: { get: () => "application/json" }, json: async () => nextReply };
};
globalThis.location = { assign: url => assigned.push(url), reload: () => assigned.push("(reload)") };

const module = await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));

const failures = [];
function expect(name, condition, detail) {
    if (!condition) {
        failures.push(`${name}: ${JSON.stringify(detail)}`);
    }
}

async function click(element, reply) {
    fetched = [];
    assigned = [];
    nextReply = reply;
    listeners.click({ target: element, preventDefault() {} });
    await new Promise(resolve => setTimeout(resolve, 20));
}

function shell() {
    return new Element({ dataset: { accountConfig: JSON.stringify({ availability: true, messages: {} }) }, classes: ["account-shell"], parent: root });
}

// Injected markup that carries its own configuration: the prefix it names is ignored, and the
// javascript: target the reply names is never followed.
const gadget = new Element({ dataset: { accountAction: "signout", accountConfig: JSON.stringify({ prefix: "https://evil.example", header: "X-Other" }) }, parent: root });
await click(gadget, { signedOut: true, nextUrl: "javascript:alert(document.domain)" });
expect("the prefix comes from the module", fetched.length === 1 && fetched[0].url === "/account/signout" && fetched[0].header === "1", fetched);
expect("a javascript: target is not followed", assigned.length === 1 && assigned[0] === "/account/signedout", assigned);

// An action element outside any account shell does nothing.
const stray = new Element({ dataset: { accountAction: "signout" }, parent: root });
await click(stray, { signedOut: true, nextUrl: "/account/signedout" });
expect("an element outside the shell is ignored", fetched.length === 0 && assigned.length === 0, { fetched, assigned });

// Inside the shell, a local target is followed and anything else falls back.
const page = shell();
const signOut = new Element({ dataset: { accountAction: "signout" }, parent: page });
await click(signOut, { signedOut: true, nextUrl: "/goodbye" });
expect("a local target is followed", assigned[0] === "/goodbye", assigned);
for (const target of ["//evil.example", "/\\evil.example", "https://evil.example", "/a\\b", "/a\u0000b", "", null]) {
    await click(signOut, { signedOut: true, nextUrl: target });
    expect(`target ${JSON.stringify(target)} falls back`, assigned[0] === "/account/signedout", assigned);
}

const removeButton = new Element({ dataset: { accountAction: "remove", accountCredential: "cred-1" }, parent: page });
await click(removeButton, { signedOut: true, nextUrl: "https://evil.example" });
expect("removing the session passkey falls back to the signed-out page", fetched[0].url === "/account/passkeys/cred-1" && assigned[0] === "/account/signedout", { fetched, assigned });

// A form the action names is read only when it sits in the same shell.
const foreignForm = new Element({ id: "account-profile", parent: root });
const profileButton = new Element({ dataset: { accountAction: "profile", accountForm: "account-profile" }, parent: page });
globalThis.FormData = class { constructor() { this.values = [["displayName", "Mallory"]]; } entries() { return this.values; } };
fetched = [];
await click(profileButton, {});
expect("a form outside the shell is not read", fetched.length === 1 && fetched[0].url === "/account/profile" && fetched[0].body.displayName === null, fetched);
void foreignForm;

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
