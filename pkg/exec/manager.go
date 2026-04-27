package exec

type WrapStrategy struct {
	LockfileCmd  []string
	LockfilePath string
	InstallCmd   []string
}

type PackageManager interface {
	Name() string
	Plan(args []string, dir string) *WrapStrategy
}
