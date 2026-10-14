//go:build integrationfault

package install

import (
	"errors"
	"os"
)

// This fixture is compiled only for disposable CI fault tests, never release artifacts.
func installationFault(stage string) error {
	if os.Getenv("TUNNELMANAGER_TEST_FAULT") == stage {
		return errors.New("disposable CI fault injected")
	}
	return nil
}
