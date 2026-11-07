//go:build !linux

package device

import (
	"github.com/userv-one/uservone-amneziawg/v3/conn"
	"github.com/userv-one/uservone-amneziawg/v3/rwcancel"
)

func (device *Device) startRouteListener(_ conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
