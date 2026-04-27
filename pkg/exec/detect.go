package exec

import "path/filepath"

func Detect(command string) PackageManager {
	base := filepath.Base(command)
	switch base {
	case "npm":
		return &NPM{}
	default:
		return nil
	}
}
