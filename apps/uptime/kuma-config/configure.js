// Applies monitors.json and the two notifications (ntfy push, email) to Uptime Kuma over
// its socket API, the same calls its web UI makes. Matched by name: missing ones are
// created, existing ones are overwritten with what's in git; monitors added by hand in the
// UI are left alone. Needs Kuma's own login turned off (Authelia does it), which makes
// Kuma log every connection in as the admin; the network policy limits who may connect.
// Secrets come from files mounted from Vault and are never printed.
"use strict";
const fs = require("fs");
const { io } = require("/app/node_modules/socket.io-client");

const KUMA = process.env.KUMA_URL || "http://uptime-kuma:3001";
const config = JSON.parse(fs.readFileSync(__dirname + "/monitors.json", "utf8"));
const secret = (name) => fs.readFileSync("/secrets/" + name, "utf8").trim();

// Same defaults as a new monitor in Kuma's UI (src/pages/EditMonitor.vue)
const MONITOR_DEFAULTS = {
    type: "http", parent: null, url: "https://", method: "GET", protocol: null,
    location: "world", ipFamily: null, interval: 60, retryInterval: 60, resendInterval: 0,
    maxretries: 0, retryOnlyOnStatusCodeFailure: false, ignoreTls: false, upsideDown: false,
    expiryNotification: false, domainExpiryNotification: false, maxredirects: 10,
    accepted_statuscodes: ["200-299"], saveResponse: false, saveErrorResponse: true,
    responseMaxLength: 1024, dns_resolve_type: "A", dns_resolve_server: "", docker_container: "",
    docker_host: null, proxyId: null, basic_auth_user: "", basic_auth_pass: "", bearer_token: "",
    mqttUsername: "", mqttPassword: "", mqttTopic: "", mqttWebsocketPath: "",
    mqttSuccessMessage: "", mqttCheckType: "keyword", authMethod: null,
    oauth_auth_method: "client_secret_basic", httpBodyEncoding: "json", kafkaProducerBrokers: [],
    kafkaProducerSaslOptions: { mechanism: "None" }, cacheBust: false, kafkaProducerSsl: false,
    kafkaProducerAllowAutoTopicCreation: false, gamedigGivenPortOnly: true, gamedigToken: "",
    remote_browser: null, screenshot_delay: 0, rabbitmqNodes: [], rabbitmqUsername: "",
    rabbitmqPassword: "", conditions: [], system_service_name: "", sshAuthMethod: "password",
    ntpStratumThreshold: 5, ntpTimeOffsetThreshold: 1000, ntpRootDispersionThreshold: 500,
    description: "",
};

const NOTIFICATIONS = [
    {
        name: "Push (ntfy)", type: "ntfy", isDefault: true, applyExisting: true, active: true,
        ntfyserverurl: "https://ntfy.sh", ntfytopic: secret("ntfy-topic"),
        ntfyAuthenticationMethod: "none", ntfyPriority: 3, ntfyPriorityDown: 5,
    },
    {
        name: "Email", type: "smtp", isDefault: true, applyExisting: true, active: true,
        smtpHost: "smtp.protonmail.ch", smtpPort: 587, smtpSecure: false, // STARTTLS on 587
        smtpIgnoreSTARTTLS: false, smtpIgnoreTLSError: false,
        smtpUsername: "noreply@agathla.com", smtpPassword: secret("smtp-password"),
        smtpFrom: "Homelab <noreply@agathla.com>", smtpTo: secret("smtp-to"),
    },
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Kuma's socket calls answer through a callback; fail on { ok: false }
function call(socket, event, ...args) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`${event}: no answer`)), 30000);
        socket.emit(event, ...args, (res) => {
            clearTimeout(timer);
            if (res && res.ok === false) reject(new Error(`${event}: ${res.msg}`));
            else resolve(res);
        });
    });
}

// The network policy lets a new pod in a few seconds after it starts, so retry the connect
async function connect() {
    for (let attempt = 1; ; attempt++) {
        const socket = io(KUMA, { transports: ["websocket"], reconnection: false, timeout: 10000 });
        const state = { monitors: null, notifications: null };
        socket.on("monitorList", (list) => { state.monitors = Object.values(list); });
        socket.on("notificationList", (list) => { state.notifications = list; });
        try {
            await new Promise((resolve, reject) => {
                socket.on("autoLogin", resolve);
                socket.on("loginRequired", () => reject(new Error(
                    "Kuma asks for a login: turn off auth in Settings > Security (Authelia does it)")));
                socket.on("connect_error", reject);
            });
            for (let i = 0; i < 100 && (!state.monitors || !state.notifications); i++) await sleep(100);
            if (!state.monitors || !state.notifications) throw new Error("no lists from Kuma");
            return { socket, state };
        } catch (e) {
            socket.close();
            if (attempt >= 10 || /login/.test(e.message)) throw e;
            console.log(`connect failed (${e.message}), retrying`);
            await sleep(3000);
        }
    }
}

// Create, or overwrite the existing one with the same name (and type family)
async function upsertMonitor(socket, state, wanted) {
    const existing = state.monitors.find((m) => m.name === wanted.name &&
        (m.type === "group") === (wanted.type === "group"));
    if (existing) {
        const monitor = { ...existing, ...MONITOR_DEFAULTS, ...wanted, id: existing.id };
        await call(socket, "editMonitor", monitor);
        console.log(`updated  ${wanted.name}`);
        return existing.id;
    }
    const res = await call(socket, "add", { ...MONITOR_DEFAULTS, ...wanted });
    console.log(`created  ${wanted.name}`);
    return res.monitorID;
}

async function main() {
    const { socket, state } = await connect();
    try {
        const notificationIDs = {};
        for (const n of NOTIFICATIONS) {
            const existing = state.notifications.find((e) => e.name === n.name);
            const res = await call(socket, "addNotification", n, existing ? existing.id : null);
            notificationIDs[res.id] = true;
            console.log(`${existing ? "updated " : "created "} notification ${n.name}`);
        }

        for (const group of config.groups) {
            const groupID = await upsertMonitor(socket, state, {
                ...config.defaults, type: "group", name: group.name, notificationIDList: notificationIDs,
            });
            for (const m of group.monitors) {
                await upsertMonitor(socket, state, {
                    ...config.defaults,
                    // certificate expiry warnings for everything served over https
                    expiryNotification: String(m.url || "").startsWith("https://"),
                    ...m,
                    parent: groupID,
                    notificationIDList: notificationIDs,
                });
            }
        }
        console.log("done");
    } finally {
        socket.close();
    }
}

main().catch((e) => { console.error("error:", e.message); process.exit(1); });
