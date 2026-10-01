package manager

import "os"

func hostnameGuess() (string, error) { return os.Hostname() }
