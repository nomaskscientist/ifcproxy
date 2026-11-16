//go:build !windows

package ask

import "os"

func openTerminal() (*Terminal, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &Terminal{In: f, Out: f}, nil
}
