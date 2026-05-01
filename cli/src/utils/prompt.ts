/**
 * Minimal interactive prompts using Node's built-in readline.
 * No external dependencies (inquirer/prompts).
 */

import { createInterface } from "node:readline";
import { c } from "./colors.js";

function ask(question: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

/**
 * Yes/no prompt. Default value used if the user just hits Enter.
 */
export async function confirm(message: string, defaultValue = true): Promise<boolean> {
  const hint = defaultValue ? c.dim("(Y/n)") : c.dim("(y/N)");
  const answer = (await ask(`${c.cyan("?")} ${message} ${hint} `)).trim().toLowerCase();
  if (answer === "") return defaultValue;
  return answer === "y" || answer === "yes";
}

/**
 * Single-select prompt with numbered options.
 */
export async function select<T extends string>(
  message: string,
  options: Array<{ value: T; label: string; hint?: string }>,
  defaultIndex = 0,
): Promise<T> {
  console.log(`${c.cyan("?")} ${message}`);
  options.forEach((opt, i) => {
    const marker = i === defaultIndex ? c.cyan("●") : c.gray("○");
    const num = c.gray(`${i + 1}.`);
    const hint = opt.hint ? c.dim(` — ${opt.hint}`) : "";
    console.log(`  ${marker} ${num} ${opt.label}${hint}`);
  });

  const answer = (await ask(`  ${c.dim(`(${defaultIndex + 1})`)} > `)).trim();
  if (answer === "") return options[defaultIndex].value;

  const idx = parseInt(answer, 10) - 1;
  if (isNaN(idx) || idx < 0 || idx >= options.length) {
    console.log(c.yellow(`${c.bold("⚠")}  Invalid choice, using default.`));
    return options[defaultIndex].value;
  }
  return options[idx].value;
}

/**
 * Multi-select prompt. User enters comma-separated numbers.
 */
export async function multiSelect<T extends string>(
  message: string,
  options: Array<{ value: T; label: string; hint?: string }>,
  defaultSelected: T[] = [],
): Promise<T[]> {
  console.log(`${c.cyan("?")} ${message} ${c.dim("(comma-separated, e.g. 1,3,4)")}`);
  options.forEach((opt, i) => {
    const checked = defaultSelected.includes(opt.value);
    const marker = checked ? c.green("☑") : c.gray("☐");
    const num = c.gray(`${i + 1}.`);
    const hint = opt.hint ? c.dim(` — ${opt.hint}`) : "";
    console.log(`  ${marker} ${num} ${opt.label}${hint}`);
  });

  const defaultDisplay = defaultSelected.length
    ? options
        .map((o, i) => (defaultSelected.includes(o.value) ? i + 1 : null))
        .filter((n): n is number => n !== null)
        .join(",")
    : "";
  const answer = (await ask(`  ${c.dim(`(${defaultDisplay})`)} > `)).trim();
  if (answer === "") return defaultSelected;

  const indices = answer
    .split(",")
    .map((s) => parseInt(s.trim(), 10) - 1)
    .filter((i) => !isNaN(i) && i >= 0 && i < options.length);

  return [...new Set(indices.map((i) => options[i].value))];
}

/**
 * Free-form text input.
 */
export async function input(message: string, defaultValue?: string): Promise<string> {
  const hint = defaultValue ? c.dim(`(${defaultValue})`) : "";
  const answer = (await ask(`${c.cyan("?")} ${message} ${hint} `)).trim();
  return answer === "" && defaultValue !== undefined ? defaultValue : answer;
}
