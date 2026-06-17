export type Logger = (
  level: string,
  message: string,
  meta?: Record<string, unknown>,
) => void;

export interface LoggerInterface {
  info: (message: string, meta?: Record<string, unknown>) => void;
  warn: (message: string, meta?: Record<string, unknown>) => void;
  error: (message: string, meta?: Record<string, unknown>) => void;
  debug: (message: string, meta?: Record<string, unknown>) => void;
}

export function createLogger(prefix?: string): LoggerInterface {
  const p = prefix ? `[${prefix}] ` : "";
  return {
    info: (msg, meta) => console.log(`${p}INFO  ${msg}`, meta ?? ""),
    warn: (msg, meta) => console.warn(`${p}WARN  ${msg}`, meta ?? ""),
    error: (msg, meta) => console.error(`${p}ERROR ${msg}`, meta ?? ""),
    debug: (msg, meta) => console.log(`${p}DEBUG ${msg}`, meta ?? ""),
  };
}

export function rawLogger(prefix?: string): Logger {
  const p = prefix ? `[${prefix}] ` : "";
  return (level, message, meta) => {
    const line = `${p}${level.toUpperCase()} ${message}`;
    if (level === "error") console.error(line, meta ?? "");
    else if (level === "warn") console.warn(line, meta ?? "");
    else console.log(line, meta ?? "");
  };
}

export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_ORDER: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 };

export interface StructuredLoggerInterface {
  info: (message: string, meta?: Record<string, unknown>) => void;
  warn: (message: string, meta?: Record<string, unknown>) => void;
  error: (message: string, meta?: Record<string, unknown>) => void;
  debug: (message: string, meta?: Record<string, unknown>) => void;
}

export function rawStructuredLogger(prefix?: string, minLevel?: LogLevel): Logger {
  const p = prefix ?? "";
  const resolvedMinLevel = minLevel ??
    (globalThis.Deno?.env.get("MIN_LOG_LEVEL") as LogLevel | undefined) ??
    "info";
  const minRank = LEVEL_ORDER[resolvedMinLevel] ?? 1;
  return (level, message, meta) => {
    const lvl = level as LogLevel;
    if ((LEVEL_ORDER[lvl] ?? 1) < minRank) return;
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      level: lvl,
      message,
      prefix: p,
      ...meta,
    });
    if (level === "error" || level === "warn") console.error(line);
    else console.log(line);
  };
}

export function createStructuredLogger(
  prefix?: string,
  minLevel?: LogLevel,
): StructuredLoggerInterface {
  const raw = rawStructuredLogger(prefix, minLevel);
  return {
    info: (message, meta) => raw("info", message, meta),
    warn: (message, meta) => raw("warn", message, meta),
    error: (message, meta) => raw("error", message, meta),
    debug: (message, meta) => raw("debug", message, meta),
  };
}

export const noopLogger: Logger = () => {};

export const noopLoggerInterface: LoggerInterface = {
  info: () => {},
  warn: () => {},
  error: () => {},
  debug: () => {},
};

export const ON_BEHALF_OF_HEADER = "x-on-behalf-of";
