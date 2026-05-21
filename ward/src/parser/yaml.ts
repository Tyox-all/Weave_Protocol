/**
 * Minimal YAML frontmatter extractor.
 *
 * We only support the subset of YAML actually used in WARD.md frontmatter:
 *   - scalar key: value pairs
 *   - quoted and unquoted strings
 *   - simple arrays [a, b, c]
 *   - block arrays with `-` items
 *
 * No anchors, no merge keys, no multi-doc. If users need richer YAML they
 * can put it in markdown sections instead.
 */

/** Extract frontmatter block from raw markdown. Returns body if no frontmatter. */
export function splitFrontmatter(source: string): {
  frontmatter: string | null;
  body: string;
} {
  if (!source.startsWith("---")) return { frontmatter: null, body: source };

  const lines = source.split("\n");
  let endIdx = -1;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i].trim() === "---" || lines[i].trim() === "...") {
      endIdx = i;
      break;
    }
  }
  if (endIdx === -1) return { frontmatter: null, body: source };

  return {
    frontmatter: lines.slice(1, endIdx).join("\n"),
    body: lines.slice(endIdx + 1).join("\n"),
  };
}

function unquote(s: string): string {
  s = s.trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  return s;
}

function coerce(raw: string): unknown {
  const s = raw.trim();
  if (s === "" || s === "~" || s === "null") return null;
  if (s === "true") return true;
  if (s === "false") return false;
  if (/^-?\d+$/.test(s)) return parseInt(s, 10);
  if (/^-?\d+\.\d+$/.test(s)) return parseFloat(s);

  // Inline array: [a, b, c]
  if (s.startsWith("[") && s.endsWith("]")) {
    const inner = s.slice(1, -1).trim();
    if (inner === "") return [];
    return inner.split(",").map((part) => coerce(unquote(part)));
  }

  // Inline object: {key: value, ...}  (rare in our spec but supported)
  if (s.startsWith("{") && s.endsWith("}")) {
    const inner = s.slice(1, -1).trim();
    const obj: Record<string, unknown> = {};
    if (inner === "") return obj;
    for (const pair of inner.split(",")) {
      const colon = pair.indexOf(":");
      if (colon === -1) continue;
      obj[unquote(pair.slice(0, colon).trim())] = coerce(unquote(pair.slice(colon + 1).trim()));
    }
    return obj;
  }

  return unquote(s);
}

/**
 * Parse a simple YAML block into a JS object.
 * Handles top-level keys and one level of nested block lists.
 */
export function parseYAML(yaml: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  const lines = yaml.split("\n");

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) {
      i++;
      continue;
    }

    const indent = line.length - line.trimStart().length;
    const colon = line.indexOf(":");
    if (colon === -1) {
      i++;
      continue;
    }

    const key = line.slice(indent, colon).trim();
    const rest = line.slice(colon + 1).trim();

    // Top-level only for frontmatter (we don't try to handle deep nesting here)
    if (indent !== 0) {
      i++;
      continue;
    }

    if (rest === "") {
      // Could be a block list or block mapping starting on next line
      const items: unknown[] = [];
      let j = i + 1;
      while (j < lines.length) {
        const nextLine = lines[j];
        const nextTrim = nextLine.trim();
        if (nextTrim === "" || nextTrim.startsWith("#")) {
          j++;
          continue;
        }
        const nextIndent = nextLine.length - nextLine.trimStart().length;
        if (nextIndent === 0) break; // back to top level
        if (nextTrim.startsWith("- ")) {
          items.push(coerce(nextTrim.slice(2)));
          j++;
          continue;
        }
        // Not a list item — abort, treat key as empty
        break;
      }
      result[key] = items;
      i = j;
    } else {
      result[key] = coerce(rest);
      i++;
    }
  }

  return result;
}
