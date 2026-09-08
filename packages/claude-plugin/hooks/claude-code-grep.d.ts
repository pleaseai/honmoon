// Grep exists at run time (the host accepts it in a tool.call matcher, and the
// plugin's command hooks have always matched it), but it is not among the 28
// built-in tools `/plugin-types` wrote on Claude Code 2.1.263, so its name
// cannot be spelled in a matcher without this augmentation. Only the fields the
// module reads are declared; drop this file if a regenerated
// `.claude/types/claude-code.d.ts` starts declaring Grep itself.
declare module 'claude-code' {
  interface BuiltinToolInputs {
    Grep: {
      /** The regular expression pattern to search for */
      pattern: string
      /** File or directory to search in */
      path?: string
    }
  }
}
