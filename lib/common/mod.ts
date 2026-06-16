export type Logger = {
  (level: string, message: string, meta?: Record<string, unknown>): void;
};

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

export const ON_BEHALF_OF_HEADER = "x-on-behalf-of";
