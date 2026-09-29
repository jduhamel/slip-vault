// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"github.com/ohler55/slip"
)

var (
	// Pkg is the vault package.
	Pkg = slip.Package{
		Name:      "vault",
		Nicknames: []string{"vault"},
		Doc:       "Home of symbols defined for the vault functions, variables, and constants.",
		PreSet:    slip.DefaultPreSet,
	}
)

func init() {
	Pkg.Initialize(map[string]*slip.VarVal{
		"*vault*": {
			Val:    &Pkg,
			Const:  true,
			Export: true,
			Doc:    `The vault package.`,
		},
	})
	defMakeSecret()
	defSecretValue()
	defSecretp()
	defSecretEqual()
	defClient()

	initConnect()

	Pkg.Initialize(nil, &Secret{}) // lock
	slip.AddPackage(&Pkg)
	slip.UserPkg.Use(&Pkg)
}
