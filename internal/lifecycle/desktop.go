package lifecycle

import "os"

// ReceiverSettings resolves the same configuration used by service management,
// so the desktop never accidentally controls a different enrollment or port.
type ReceiverSettings struct {
	Executable     string
	ConfigPath     string
	StateDir       string
	ControlAddress string
}

func ResolveReceiver(configPath string) (ReceiverSettings, error) {
	c, err := loadConfig(configPath)
	if err != nil {
		return ReceiverSettings{}, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ReceiverSettings{}, err
	}
	spec, err := makeSpec(c, "receiver", home, os.Getenv("PATH"))
	if err != nil {
		return ReceiverSettings{}, err
	}
	return ReceiverSettings{spec.executable, spec.args[1], spec.args[3], spec.args[5]}, nil
}
