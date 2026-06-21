"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityPermissionGate = void 0;
exports.findProtectedCidr = findProtectedCidr;
const PROTECTED_ENTRIES = [
    // Loopback — RFC 1122 §3.2.1.3: 127.0.0.0/8 is reserved for the host.
    { label: "loopback", network: "127.0.0.0", prefix: 8 },
    // RFC 1918 private network — never block the lab gateway.
    { label: "rfc1918-gateway", network: "10.0.0.1", prefix: 32 },
    // Common default gateway. Exact match only — private RFC 1918 elsewhere
    // is fine to target.
    { label: "default-gateway", network: "192.168.1.1", prefix: 32 },
];
/**
 * Convert dotted-quad IPv4 to a 32-bit integer.
 * Returns ``null`` if the input is malformed so callers can fall back to a
 * safe deny instead of crashing inside the permission gate.
 */
function ipv4ToInt(ip) {
    const parts = ip.split(".");
    if (parts.length !== 4)
        return null;
    let acc = 0;
    for (const part of parts) {
        if (!/^\d+$/.test(part))
            return null;
        const n = Number(part);
        if (n < 0 || n > 255)
            return null;
        acc = (acc << 8) | n;
    }
    return acc >>> 0;
}
/**
 * Return the entry from ``PROTECTED_ENTRIES`` that ``target`` falls inside,
 * or ``null`` if the target is not on any protected network.
 *
 * Real CIDR match — ``protectedCidrs.includes(...)`` substring matching
 * misses ``127.0.0.5`` (loopback range) because the ``/8`` suffix does not
 * appear in the IP literal. This bitmask check covers every address in
 * each protected range.
 */
function findProtectedCidr(target) {
    if (!target)
        return null;
    const targetInt = ipv4ToInt(target);
    if (targetInt === null)
        return null;
    for (const entry of PROTECTED_ENTRIES) {
        const networkInt = ipv4ToInt(entry.network);
        if (networkInt === null)
            continue;
        if (entry.prefix === 0)
            return entry;
        if (entry.prefix > 32)
            continue;
        const mask = entry.prefix === 32 ? 0xffffffff : (~((1 << (32 - entry.prefix)) - 1)) >>> 0;
        if ((targetInt & mask) === (networkInt & mask)) {
            return entry;
        }
    }
    return null;
}
class SecurityPermissionGate {
    evaluate(action, target) {
        if (!action.startsWith("simulate_")) {
            return {
                action,
                allowed: false,
                reason: "Only simulated actions are allowed in lab mode.",
            };
        }
        const protectedCidr = findProtectedCidr(target);
        if (protectedCidr) {
            return {
                action,
                allowed: false,
                reason: `Target ${target} is a protected asset or management address (${protectedCidr.label}).`,
            };
        }
        const requiresApproval = ["simulate_block_ip", "simulate_quarantine_host", "simulate_disable_user"];
        if (requiresApproval.includes(action)) {
            return {
                action,
                allowed: true,
                reason: "Simulated action allowed but requires human operator approval.",
            };
        }
        return {
            action,
            allowed: true,
            reason: "Action is low risk and automatically approved.",
        };
    }
}
exports.SecurityPermissionGate = SecurityPermissionGate;
