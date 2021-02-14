package build

import (
	"github.com/uplo-tech/log"
)

var (
	// logOptions contains the build options required by Critical.
	logOptions = log.Options{
		BinaryName:   "uplomux",
		BugReportURL: IssuesURL,
		Debug:        DEBUG,
		Release:      buildReleaseType(),
		Version:      Version,
	}
)

// Critical should be called if a sanity check has failed, indicating developer
// error. Critical is called with an extended message guiding the user to the
// issue tracker on Github. If the program does not panic, the call stack for
// the running goroutine is printed to help determine the error.
func Critical(v ...interface{}) {
	logOptions.Critical(v...)
}

// buildReleaseType returns the release type for this build, defaulting to
// Release.
func buildReleaseType() log.ReleaseType {
	switch Release {
	case Standard:
		return log.Release
	case Dev:
		return log.Dev
	case Testing:
		return log.Testing
	default:
		return log.Release
	}
}
