package packagemanager

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/Masterminds/semver"
	"github.com/pkg/errors"
	"github.com/vercel/turbo/cli/internal/fs"
	"github.com/vercel/turbo/cli/internal/lockfile"
	"github.com/vercel/turbo/cli/internal/turbopath"
	"github.com/vercel/turbo/cli/internal/util"
)

var nodejsBerry = PackageManager{
	Name:       "nodejs-berry",
	Slug:       "yarn",
	Command:    "yarn",
	Specfile:   "package.json",
	Lockfile:   "yarn.lock",
	PackageDir: "node_modules",

	getWorkspaceGlobs: func(rootpath turbopath.AbsoluteSystemPath) ([]string, error) {
		pkg, err := fs.ReadPackageJSON(rootpath.UntypedJoin("package.json"))
		if err != nil {
			return nil, fmt.Errorf("package.json: %w", err)
		}
		if len(pkg.Workspaces) == 0 {
			return nil, fmt.Errorf("package.json: no workspaces found. Turborepo requires Yarn workspaces to be defined in the root package.json")
		}
		return pkg.Workspaces, nil
	},

	getWorkspaceIgnores: func(pm PackageManager, rootpath turbopath.AbsoluteSystemPath) ([]string, error) {
		// Matches upstream values:
		// Key code: https://github.com/yarnpkg/berry/blob/8e0c4b897b0881878a1f901230ea49b7c8113fbe/packages/yarnpkg-core/sources/Workspace.ts#L64-L70
		return []string{
			"**/node_modules",
			"**/.git",
			"**/.yarn",
		}, nil
	},

	canPrune: func(cwd turbopath.AbsoluteSystemPath) (bool, error) {
		if isNMLinker, err := util.IsNMLinker(cwd.ToStringDuringMigration()); err != nil {
			return false, errors.Wrap(err, "could not determine if yarn is using `nodeLinker: node-modules`")
		} else if !isNMLinker {
			return false, errors.New("only yarn v2/v3 with `nodeLinker: node-modules` is supported at this time")
		}
		return true, nil
	},

	// Versions newer than 2.0 are berry, and before that we simply call them yarn.
	Matches: func(manager string, version string) (bool, error) {
		if manager != "yarn" {
			return false, nil
		}

		v, err := semver.NewVersion(version)
		if err != nil {
			return false, fmt.Errorf("could not parse yarn version: %w", err)
		}
		// -0 allows pre-releases versions to be considered valid
		c, err := semver.NewConstraint(">=2.0.0-0")
		if err != nil {
			return false, fmt.Errorf("could not create constraint: %w", err)
		}

		return c.Check(v), nil
	},

	// Detect for berry needs to identify which version of yarn is running on the system.
	// Further, berry can be configured in an incompatible way, so we check for compatibility here as well.
	detect: func(projectDirectory turbopath.AbsoluteSystemPath, packageManager *PackageManager) (bool, error) {
		specfileExists := projectDirectory.UntypedJoin(packageManager.Specfile).FileExists()
		lockfileExists := projectDirectory.UntypedJoin(packageManager.Lockfile).FileExists()

		// Short-circuit, definitely not Yarn.
		if !specfileExists || !lockfileExists {
			return false, nil
		}

		cmd := exec.Command("yarn", "--version")
		cmd.Dir = projectDirectory.ToString()
		out, err := cmd.Output()
		if err != nil {
			return false, fmt.Errorf("could not detect yarn version: %w", err)
		}

		// See if we're a match when we compare these two things.
		matches, _ := packageManager.Matches(packageManager.Slug, string(out))

		// Short-circuit, definitely not Berry because version number says we're Yarn.
		if !matches {
			return false, nil
		}

		// We're Berry!

		// Check for supported configuration.
		isNMLinker, err := util.IsNMLinker(projectDirectory.ToStringDuringMigration())

		if err != nil {
			// Failed to read the linker state, so we treat an unknown configuration as a failure.
			return false, fmt.Errorf("could not check if yarn is using nm-linker: %w", err)
		} else if !isNMLinker {
			// Not using nm-linker, so unsupported configuration.
			return false, fmt.Errorf("only yarn nm-linker is supported")
		}

		// Berry, supported configuration.
		return true, nil
	},

	readLockfile: func(rootPackageJSON *fs.PackageJSON, contents []byte) (lockfile.Lockfile, error) {
		resolutions := make(map[berryResolution]string, len(rootPackageJSON.Resolutions))
		for rawResolution, version := range rootPackageJSON.Resolutions {
			resolution, err := parseBerryResolution(rawResolution)
			if err != nil {
				return nil, errors.Wrapf(err, "Unable to parse 'resolutions' entry: %s", rawResolution)
			}
			resolutions[resolution] = version
		}
		// TODO do something with resolutions
		return lockfile.DecodeBerryLockfile(contents)
	},

	prunePatches: func(pkgJSON *fs.PackageJSON, patches []turbopath.AnchoredUnixPath) error {
		pkgJSON.Mu.Lock()
		defer pkgJSON.Mu.Unlock()

		keysToDelete := []string{}
		resolutions, ok := pkgJSON.RawJSON["resolutions"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("Invalid structure for resolutions field in package.json")
		}

		for dependency, untypedPatch := range resolutions {
			inPatches := false
			patch, ok := untypedPatch.(string)
			if !ok {
				return fmt.Errorf("Expected value of %s in package.json to be a string, got %v", dependency, untypedPatch)
			}

			for _, wantedPatch := range patches {
				if strings.HasSuffix(patch, wantedPatch.ToString()) {
					inPatches = true
					break
				}
			}

			// We only want to delete unused patches as they are the only ones that throw if unused
			if !inPatches && strings.HasSuffix(patch, ".patch") {
				keysToDelete = append(keysToDelete, dependency)
			}
		}

		for _, key := range keysToDelete {
			delete(resolutions, key)
		}

		return nil
	},
}

// Berry resolution grammar comes from
// https://github.com/yarnpkg/berry/blob/554257087edb4a103633e808253323fb9a21250d/packages/yarnpkg-parsers/sources/grammars/resolution.pegjs
// The parser is written in the style of a parser combinator, but done by hand
// since I didn't love the Go parser combinator libraries I saw and pulling in
// a parser generator seemed overkill for just this simple grammar.

type berrySpecifier struct {
	fullName    string
	description string
}

type berryResolution struct {
	// Can be zero
	from       berrySpecifier
	descriptor berrySpecifier
}

func parseBerryResolution(input string) (berryResolution, error) {
	var resolution berryResolution
	out, descriptor, err := parseBerrySpecifier(input)
	if err != nil {
		return resolution, err
	}
	resolution.descriptor = descriptor
	if len(out) != 0 && out[0] == '/' {
		from := descriptor
		descOut, descriptor, err := parseBerrySpecifier(out[1:])
		if err == nil {
			resolution.from = from
			resolution.descriptor = descriptor
			out = descOut
		}
	}
	if len(out) != 0 {
		return berryResolution{}, fmt.Errorf("Leftover input when parsing resolution: '%s'", out)
	}
	return resolution, nil
}

func parseBerrySpecifier(input string) (string, berrySpecifier, error) {
	var specifier berrySpecifier
	out, fullName, err := parseFullName(input)
	if err != nil {
		return input, specifier, errors.Wrapf(err, "Invalid specifier: %s", input)
	}
	specifier.fullName = fullName
	if len(out) != 0 && out[0] == '@' {
		descOut, description, err := parseDescription(out[1:])
		// If we happen upon an error we fall back to simple specifier
		if err != nil {
			return out, specifier, nil
		}
		specifier.description = description
		out = descOut
	}
	return out, specifier, nil
}

func parseFullName(input string) (out string, fullName string, err error) {
	if strings.HasPrefix(input, "@") {
		input1, scope, err := parseIdent(input[1:])
		if err != nil {
			return input, "", err
		}
		if len(input1) == 0 || input1[0] != '/' {
			return input, "", fmt.Errorf("Expected to find '/' after '%s' in '%s'", scope, input)
		}
		out, name, err := parseIdent(input1[1:])
		if err != nil {
			return input, "", err
		}
		return out, fmt.Sprintf("@%s/%s", scope, name), nil
	}
	return parseIdent(input)
}

// A string parser produces a parse state with type string
type stringParser func(string) (string, string, error)

var _identRegexp = regexp.MustCompile("^[^/@]+")
var _descriptionRegexp = regexp.MustCompile("^[^/]+")

var parseIdent = regexpParser("ident", _identRegexp)
var parseDescription = regexpParser("description", _descriptionRegexp)

// Takes a regexp and makes a string parser out of it
func regexpParser(name string, regex *regexp.Regexp) stringParser {
	return func(input string) (string, string, error) {
		text := _identRegexp.FindString(input)
		if text == "" {
			return input, "", fmt.Errorf("Invalid %s: %s", name, input)
		}
		out := input[len(text):]
		return out, text, nil
	}
}
