//go:build windows

package ask

import "os"

type consoleIn struct {
	*os.File
	out *os.File
}

func (c consoleIn) Close() error {
	errOut := c.out.Close()
	if err := c.File.Close(); err != nil {
		return err
	}
	return errOut
}

func openTerminal() (*Terminal, error) {
	in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		in.Close()
		return nil, err
	}
	return &Terminal{In: consoleIn{File: in, out: out}, Out: out}, nil
}
