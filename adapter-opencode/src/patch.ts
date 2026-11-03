/**
 * The files an OpenCode apply_patch touches (its patchText). The patch
 * format, shared with Codex, marks each file:
 *
 *   *** Add File: <path>       new file      → write
 *   *** Update File: <path>    edit in place → write
 *   *** Move to: <path>        rename target → write
 *   *** Delete File: <path>    removal       → delete
 *
 * Paths are relative to the session cwd unless absolute.
 */

export interface PatchTargets {
  writes: string[];
  deletes: string[];
}

const MARKER = /^\*\*\* (Add File|Update File|Move to|Delete File):\s*(.+?)\s*$/;

export function patchTargets(patch: string): PatchTargets {
  const writes: string[] = [];
  const deletes: string[] = [];
  for (const line of patch.split(/\r?\n/)) {
    const m = MARKER.exec(line);
    if (!m) continue;
    (m[1] === 'Delete File' ? deletes : writes).push(m[2]);
  }
  return { writes, deletes };
}
