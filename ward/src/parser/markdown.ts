/**
 * Split a markdown body into a map of `{ "section name": "section body" }`
 * keyed by H2 headings (`## Section Name`).
 *
 * The section name is normalized (lowercased, alphanumeric only) so that
 * `## Multi-Agent` and `## multi agent` produce the same key.
 */

export interface MarkdownSection {
  /** Original heading text. */
  title: string;
  /** Normalized key. */
  key: string;
  /** Body of the section (content under the heading, up to the next H2). */
  body: string;
}

export function splitSections(body: string): MarkdownSection[] {
  const lines = body.split("\n");
  const sections: MarkdownSection[] = [];
  let current: MarkdownSection | null = null;
  let currentLines: string[] = [];

  for (const line of lines) {
    const h2Match = /^##\s+(.+?)\s*$/.exec(line);
    if (h2Match) {
      // Flush previous section
      if (current) {
        current.body = currentLines.join("\n").trim();
        sections.push(current);
      }
      const title = h2Match[1].trim();
      current = { title, key: normalizeKey(title), body: "" };
      currentLines = [];
    } else if (current) {
      currentLines.push(line);
    }
    // Lines before the first H2 are ignored (typically just the H1 title)
  }

  if (current) {
    current.body = currentLines.join("\n").trim();
    sections.push(current);
  }

  return sections;
}

export function normalizeKey(title: string): string {
  return title.toLowerCase().replace(/[^a-z0-9]+/g, "");
}

/**
 * Extract a YAML-like block from a section body. Many WARD sections use the
 * pattern of bare `key: value` and `-` list items inside markdown, optionally
 * wrapped in a ```yaml fenced code block.
 */
export function extractStructuredBlock(sectionBody: string): string {
  // Prefer explicit fenced yaml block if present
  const fenced = /```ya?ml\s*\n([\s\S]*?)\n```/i.exec(sectionBody);
  if (fenced) return fenced[1];

  // Otherwise just use the section body as-is. Strip code fences.
  return sectionBody.replace(/```[^\n]*\n?/g, "").trim();
}
