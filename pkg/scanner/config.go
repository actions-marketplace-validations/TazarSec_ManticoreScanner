package scanner

import "github.com/TazarSec/ManticoreScanner/pkg/auth"

type Config struct {
	Auth              auth.Authenticator
	APIBaseURL        string
	TimeoutSec        int
	HTTPTimeoutSec    int
	FailOn            float64
	Format            string
	OutputPath        string
	InputPath         string
	Production        bool
	PostToVCS         bool
	IgnoreList        []string
	Quiet             bool
	Verbose           bool
	Insecure          bool
	IncludeTransitive bool
	OnError           string
}
