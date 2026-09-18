import path from "node:path";
import { pathToFileURL } from "node:url";

// Read literal argv only, never evaluate a saved command. Shell expansions,
// pipelines, redirects, wrappers, and extra arguments are not ours to rewrite.
function literalArgs(command, shell) {
  const ps = shell === "powershell";
  if (ps) command = command.replace(/^\s*&\s+/, "");
  const single = (c) => ps ? /['\u2018-\u201b]/u.test(c) : c === "'";
  const args = [];
  let word = "", quote = null, started = false;
  for (let i = 0; i < command.length; i++) {
    const c = command[i], next = command[i + 1];
    if (c === "\0" || (!quote && /[\r\n]/.test(c))) return null;
    if (quote === "single") {
      if (single(c)) {
        if (ps && next && single(next)) { word += next; i++; }
        else quote = null;
      } else word += c;
    } else if ((!ps && c === "\\") || (ps && c === "`")) {
      if (next === undefined) return null;
      if (!ps && quote === "double" && !/[\\"$`\n]/.test(next)) word += c;
      else {
        // PowerShell letter escapes (e.g. `n) are not literal path characters.
        if (ps && /[a-z0-9]/i.test(next)) return null;
        word += next;
        i++;
      }
      started = true;
    } else if (quote === "double") {
      if (c === '"') {
        if (ps && next === '"') { word += next; i++; }
        else quote = null;
      } else if (c === "$" || (!ps && c === "`")) return null;
      else word += c;
    } else if (single(c) || c === '"') {
      quote = single(c) ? "single" : "double";
      started = true;
    } else if (/\s/.test(c)) {
      if (started) { args.push(word); word = ""; started = false; }
    } else {
      if (/[|&;<>(){}\[\]*?!#$~`]/.test(c)) return null;
      word += c;
      started = true;
    }
  }
  if (quote) return null;
  if (started) args.push(word);
  return args;
}

function nativePath(file, cwd) {
  if (process.platform === "win32") {
    // Git Bash's /c/path and native C:/path identify the same script.
    file = file.replace(/^\/([a-z])\//i, "$1:/");
    return path.resolve(cwd, file).toLowerCase();
  }
  return path.resolve(cwd, file);
}

function isThisHook(hook, self, cwd) {
  if (hook.type !== "command" || typeof hook.command !== "string" || hook.args !== undefined) return false;
  const shell = hook.shell ?? "bash";
  if (!["bash", "powershell"].includes(shell)) return false;
  // Match precisely what pre-portability init emitted, even if URL encoding,
  // spaces, or the duplicated Windows drive made it an invalid shell command.
  const oldSelf = path.resolve(pathToFileURL(self).pathname);
  if (hook.command === `node ${oldSelf} hook`) return true;
  const args = literalArgs(hook.command, shell);
  if (!args || args.length !== 3 || args[2] !== "hook") return false;
  const interpreter = args[0].split(/[\\/]/).at(-1);
  if (!/^node(?:js)?(?:\.exe)?$/i.test(interpreter) &&
      nativePath(args[0], cwd) !== nativePath(process.execPath, cwd)) return false;
  return nativePath(args[1], cwd) === nativePath(self, cwd);
}

// Only default, unconditional groups are managed by init. Preserve restricted
// matchers and other hand-authored scopes, as well as unrelated sibling hooks.
function defaultGroup(group) {
  return Object.keys(group).every((key) => key === "hooks" || key === "matcher") &&
    [undefined, "", "*"].includes(group.matcher);
}

export function installHooks(existing, requested, self, cwd) {
  const counts = { installed: 0, replaced: 0, removed: 0 };
  for (const [event, defaults] of Object.entries(requested)) {
    const desired = defaults[0].hooks[0];
    let found = false;
    const groups = [];
    for (const group of existing[event] ?? []) {
      if (!defaultGroup(group)) { groups.push(group); continue; }
      const hooks = [];
      let removed = false;
      for (const hook of group.hooks ?? []) {
        const exact = hook.type === "command" && hook.args === undefined &&
          hook.command === desired.command && (hook.shell ?? "bash") === desired.shell;
        if (!exact && !isThisHook(hook, self, cwd)) { hooks.push(hook); continue; }
        if (found) { counts.removed++; removed = true; continue; }
        found = true;
        if (exact) hooks.push(hook);
        else { hooks.push({ ...hook, ...desired }); counts.replaced++; }
      }
      if (hooks.length || !removed) groups.push({ ...group, hooks });
    }
    if (!found) { groups.push(...defaults); counts.installed++; }
    existing[event] = groups;
  }
  return counts;
}
