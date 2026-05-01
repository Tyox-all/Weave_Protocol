/**
 * ANSI color utilities — no external deps.
 */

const supportsColor =
  process.stdout.isTTY &&
  process.env.TERM !== "dumb" &&
  !process.env.NO_COLOR;

function wrap(open: string, close: string) {
  return (s: string) => (supportsColor ? `${open}${s}${close}` : s);
}

export const c = {
  reset: "\x1b[0m",
  bold: wrap("\x1b[1m", "\x1b[22m"),
  dim: wrap("\x1b[2m", "\x1b[22m"),
  red: wrap("\x1b[31m", "\x1b[39m"),
  green: wrap("\x1b[32m", "\x1b[39m"),
  yellow: wrap("\x1b[33m", "\x1b[39m"),
  blue: wrap("\x1b[34m", "\x1b[39m"),
  magenta: wrap("\x1b[35m", "\x1b[39m"),
  cyan: wrap("\x1b[36m", "\x1b[39m"),
  gray: wrap("\x1b[90m", "\x1b[39m"),
};

export const symbols = {
  check: "✓",
  cross: "✗",
  warning: "⚠",
  info: "ℹ",
  arrow: "→",
  bullet: "•",
  spider: "🕸️",
  shield: "🛡️",
  vault: "🏛️",
  judge: "⚖️",
  council: "👥",
  watcher: "🔍",
  customs: "🛂",
  bridge: "🔗",
  python: "🐍",
  api: "🔌",
};

export function banner(): string {
  return `
${c.cyan(c.bold("🕸️  Weave Protocol CLI"))}
${c.gray("Enterprise security for AI agents")}
`;
}

export function divider(): string {
  return c.gray("─".repeat(60));
}

export function header(title: string): string {
  return `\n${c.bold(title)}\n${divider()}`;
}
