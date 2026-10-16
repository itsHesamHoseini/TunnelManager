//go:build !linux

package nodeops

import (
	"context"
	"errors"
)

func mutationLock(context.Context, string) (func(), error) {
	return nil, errors.New("native Linux locking required")
}
