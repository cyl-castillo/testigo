// Command hooks run through sh/Git Bash by default. PowerShell uses a
// different literal-string syntax and needs & to invoke a quoted executable.
// These are shell command strings, not cmd.exe or .bat syntax.
export function hookCommand(executable, script, shell = "bash") {
  if (shell === "powershell") {
    // PowerShell also treats curly single quotes as string delimiters.
    const quote = (s) => `'${s.replace(/['\u2018-\u201b]/g, (c) => c + c)}'`;
    return `& ${quote(executable)} ${quote(script)} hook`;
  }
  if (shell !== "bash") throw new Error(`unsupported hook shell: ${shell}`);
  const quote = (s) => `'${s.replaceAll("'", "'\"'\"'")}'`;
  // Git Bash accepts Windows drive and UNC paths with forward slashes.
  const native = (s) => process.platform === "win32" ? s.replaceAll("\\", "/") : s;
  return `${quote(native(executable))} ${quote(native(script))} hook`;
}
