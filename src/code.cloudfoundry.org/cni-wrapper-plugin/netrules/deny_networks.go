package netrules

type DenyNetworks struct {
	Always  []string
	Running []string
	Staging []string
}
