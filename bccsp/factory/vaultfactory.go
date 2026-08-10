/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/hyperledger/fabric/bccsp/vault"
	"github.com/pkg/errors"
)

const (
	// VaultBasedFactoryName is the name of the factory of the HashiCorp
	// Vault Transit-based BCCSP implementation.
	VaultBasedFactoryName = "VAULT"
)

// VaultFactory is the factory of the HashiCorp Vault-based BCCSP.
type VaultFactory struct{}

// Name returns the name of this factory
func (f *VaultFactory) Name() string {
	return VaultBasedFactoryName
}

// Get returns an instance of BCCSP using Opts.
func (f *VaultFactory) Get(config *FactoryOpts) (bccsp.BCCSP, error) {
	if config == nil || config.VAULT == nil {
		return nil, errors.New("Invalid config. It must not be nil.")
	}

	vaultOpts := *config.VAULT

	// The Transit engine holds the private material, so an ephemeral in-memory
	// key store is enough for the software fallback.
	ks := sw.NewDummyKeyStore()

	return vault.New(vaultOpts, ks)
}
