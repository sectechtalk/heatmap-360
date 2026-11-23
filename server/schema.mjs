// Strict schema for uploads from the scanner. Anyone can post to /api/scans, so every field is typed and bounded and
// unknown fields are rejected. Nothing in an upload is ever executed or used to build a command, path or URL.
import Ajv from 'ajv';

const str = (max = 200) => ({ type: ['string', 'null'], maxLength: max });
const int = (min = 0, max = 2 ** 31) => ({ type: ['integer', 'null'], minimum: min, maximum: max });
const num = (min = 0, max = 1e9) => ({ type: ['number', 'null'], minimum: min, maximum: max });
const bool = { type: ['boolean', 'null'] };
const day = { type: ['string', 'null'], pattern: '^\\d{4}-\\d{2}-\\d{2}$' };
const obj = (properties, required = []) => ({ type: ['object', 'null'], additionalProperties: false, properties, required });
const arr = (items, max) => ({ type: 'array', maxItems: max, items });

const LATENCY = obj({ sent: int(0, 1000), received: int(0, 1000), lossPercent: num(0, 100), minMs: num(0, 1e6), avgMs: num(0, 1e6), maxMs: num(0, 1e6), jitterMs: num(0, 1e6) });

export const INVENTORY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['schema', 'clientVersion', 'collectedAt', 'machineId'],
  properties: {
    schema: { const: 'hm360.inventory/1' },
    clientVersion: { type: 'string', pattern: '^\\d+\\.\\d+\\.\\d+$' },
    collectedAt: { type: 'string', format: 'date-time', maxLength: 40 },
    machineId: { type: 'string', pattern: '^[0-9a-f]{16}$' },
    uptimeHours: num(0, 1e6),
    pendingReboot: bool,
    os: obj({ name: str(120), displayVersion: str(20), build: int(0, 999999), ubr: int(0, 999999), edition: str(60), architecture: str(30) }),
    updates: arr(obj({ id: str(20), description: str(80), installedOn: day }), 1000),
    health: obj({
      defender: obj({ enabled: bool, realTime: bool, signatureAgeDays: int(0, 100000), engineVersion: str(40) }),
      bitlocker: obj({ protection: str(20) }),
      secureBoot: bool,
      tpm: obj({ present: bool, ready: bool, manufacturerVersion: str(60) }),
      firewall: obj({ domain: bool, private: bool, public: bool }),
    }),
    hardware: obj({
      system: obj({ manufacturer: str(100), model: str(120), family: str(120) }),
      memoryGB: num(0, 1e6),
      bios: obj({ vendor: str(100), version: str(100), releaseDate: day }),
      baseboard: obj({ manufacturer: str(100), product: str(100), version: str(100) }),
      cpu: arr(obj({ name: str(160), manufacturer: str(60) }), 16),
      disks: arr(obj({ model: str(120), firmware: str(60), mediaType: str(30), busType: str(30), sizeGB: num(0, 1e7),
        // Since scanner 1.2.0 (reliability counters need administrator rights).
        health: str(30), wearPercent: num(0, 100), temperatureC: num(0, 200), temperatureMaxC: num(0, 200),
        readErrorsUncorrected: num(0, 1e15), writeErrorsUncorrected: num(0, 1e15), powerOnHours: num(0, 1e7) }), 64),
      battery: obj({ designMWh: num(0, 1e7), fullMWh: num(0, 1e7), cycleCount: int(0, 1e6), healthPercent: num(0, 1000) }),
      volumes: arr(obj({ drive: { type: ['string', 'null'], pattern: '^[A-Za-z]:$' }, sizeGB: num(0, 1e7), freeGB: num(0, 1e7) }), 64),
      devices: arr(obj({ class: str(30), name: str(200), manufacturer: str(120), driverProvider: str(120), driverVersion: str(60), driverDate: day }), 1000),
    }),
    // Since scanner 1.1.0. Counts per provider and event ID only, never message text.
    eventLog: obj({
      days: int(1, 90),
      entries: arr(obj({ log: { type: 'string', enum: ['System', 'Application'] }, provider: str(200), eventId: int(0, 65535), level: { type: 'string', enum: ['critical', 'error', 'warning'] },
        count: int(1, 1e7), lastSeen: { type: ['string', 'null'], format: 'date-time', maxLength: 40 } }, ['log', 'eventId']), 200),
    }, ['entries']),
    // Since scanner 1.1.0. Physical adapters only; settings come from an allowlist. No names, addresses or network names.
    network: obj({
      adapters: arr(obj({ description: str(200), mediaType: str(40), status: str(30), linkSpeedMbps: num(0, 1e7), fullDuplex: bool,
        driverVersion: str(60), driverDate: day, driverProvider: str(120), powerSaving: str(30),
        settings: arr(obj({ keyword: { type: 'string', pattern: '^\\*?[A-Za-z0-9]{1,60}$' }, name: str(120), value: str(120) }, ['keyword']), 60) }), 32),
      wifi: obj({ radioType: str(40), band: str(30), channel: int(0, 1000), signalPercent: int(0, 100), receiveMbps: num(0, 1e6), transmitMbps: num(0, 1e6) }),
    }, ['adapters']),
    // Since scanner 1.2.0. No addresses: the gateway is pinged but its address is not sent.
    networkHealth: obj({
      via: { type: ['string', 'null'], enum: ['wifi', 'wired', 'other', null] },
      gateway: LATENCY, internet: LATENCY,
      dns: obj({ ms: num(0, 1e6), ok: bool }),
      speed: obj({ downloadMbps: num(0, 1e6), uploadMbps: num(0, 1e6), bytesDown: num(0, 1e10), bytesUp: num(0, 1e10), server: str(60) }),
      speedSkipped: bool,
    }),
    apps: arr(obj({ name: str(260), version: str(80), publisher: str(200) }), 3000),
    winget: arr(obj({ id: { type: 'string', pattern: '^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$' }, version: str(80), source: str(40) }, ['id']), 3000),
    errors: arr({ type: 'string', maxLength: 500 }, 100),
  },
};

const ajv = new Ajv({ allErrors: false, strict: true, allowUnionTypes: true });
ajv.addFormat('date-time', s => !Number.isNaN(Date.parse(s)));
const validate = ajv.compile(INVENTORY_SCHEMA);

const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const USER_PATH = /(\\Users\\)[^\\]+/gi;

// Defense in depth after the scanner's own anonymizer: strip anything that still looks personal.
export function scrub(value) {
  if (typeof value === 'string') return value.replace(EMAIL, 'redacted@example.invalid').replace(USER_PATH, '$1redacted');
  if (Array.isArray(value)) return value.map(scrub);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, scrub(v)]));
  return value;
}

export function checkInventory(body) {
  if (!validate(body)) {
    const e = validate.errors[0];
    return { ok: false, error: `${e.instancePath || 'body'} ${e.message}`.slice(0, 200) };
  }
  return { ok: true, inventory: scrub(body) };
}
