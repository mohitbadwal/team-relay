// Package skills bundles the teammate instructions with the native installer.
package skills

import "embed"

// Files is deliberately limited to the two teammate roles. Admin instructions
// are not installed on teammate machines.
//
//go:embed requester/SKILL.md recipient/SKILL.md
var Files embed.FS
