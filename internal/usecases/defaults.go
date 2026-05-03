package usecases

// Defaults returns every built-in use case the runner knows about.
//
// The catalog is split across defaults_windows.go / defaults_linux.go /
// defaults_xp.go to keep each file readable; this function just stitches them
// in display order.
func Defaults() []UseCase {
	out := make([]UseCase, 0, 28)
	out = append(out, windowsUseCases()...)
	out = append(out, linuxUseCases()...)
	out = append(out, crossPlatformUseCases()...)
	return out
}
