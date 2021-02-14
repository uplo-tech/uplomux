package deps

// ProdDependencies are the default production dependencies.
var ProdDependencies = &ProductionDependencies{}

type (
	// Dependencies defines dependencies used by all of Uplo's modules. Custom
	// dependencies can be created to inject certain behavior during testing.
	Dependencies interface {
		// Disrupt can be inserted in the code as a way to inject problems,
		// such as a network call that take 10 minutes or a disk write that
		// never completes. disrupt will return true if the disruption is
		// forcibly triggered. In production, disrupt will always return false.
		Disrupt(string) bool
	}
)

type (
	// ProductionDependencies are the dependencies used in a Release or Debug
	// production build
	ProductionDependencies struct{}
)

// Disrupt can be used to inject specific behavior into a module by overwriting
// it using a custom dependency
func (pd *ProductionDependencies) Disrupt(string) bool {
	return false
}
