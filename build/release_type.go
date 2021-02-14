package build

type (
	// ReleaseType is the type of the release.
	ReleaseType uint
)

const (
	// ReleaseTypeError is an uninitialized ReleaseType.
	ReleaseTypeError ReleaseType = iota
	// Standard is the release type used for production builds.
	Standard
	// Dev is the release type used for dev builds.
	Dev
	// Testing is the release type used for testing builds.
	Testing
)
