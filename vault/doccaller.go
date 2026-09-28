// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import "github.com/ohler55/slip"

// DocCaller is a caller used for documentation only.
type DocCaller struct {
	Text string
}

// Call returns nil.
func (caller *DocCaller) Call(_ *slip.Scope, _ slip.List, _ int) slip.Object {
	return nil
}

// Docs returns the documentation for the caller.
func (caller *DocCaller) Docs() string {
	return caller.Text
}
