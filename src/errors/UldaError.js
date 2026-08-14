const PRIVATE_DETAIL_KEYS = new Set([
  "origin",
  "blocks",
  "sigBytes",
  "bytes",
  "raw",
  "secret",
  "privateKey",
  "preimage"
]);

function isPlainObject(value) {
  if (value === null || typeof value !== "object") return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function sanitizeDetails(value) {
  if (Array.isArray(value)) return value.map(item => sanitizeDetails(item));
  if (!isPlainObject(value)) return value;

  const sanitized = {};
  for (const [key, entry] of Object.entries(value)) {
    if (PRIVATE_DETAIL_KEYS.has(key)) continue;
    sanitized[key] = sanitizeDetails(entry);
  }
  return sanitized;
}

export class UldaError extends Error {
  constructor(code, message, options = {}) {
    super(message, { cause: options.cause });
    this.name = "UldaError";
    this.code = code;
    this.operation = options.operation;
    this.details = options.details;
    this.cause = options.cause;
  }

  toLogObject() {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      operation: this.operation,
      details: sanitizeDetails(this.details),
      causeName: this.cause?.name,
      causeMessage: this.cause?.message
    };
  }
}
