package lockfile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Masterminds/semver"
	"github.com/pkg/errors"
	"github.com/vercel/turborepo/cli/internal/turbopath"
	"gopkg.in/yaml.v3"
)

var _multipleKeyRegex = regexp.MustCompile(" *, *")

// A tag cannot start with a "v"
var _tagRegex = regexp.MustCompile("^[a-zA-Z0-9.-_-[v]][a-zA-Z0-9._-]*$")

var _metadataKey = "__metadata"

type _void struct{}

// BerryLockfileEntry package information from yarn lockfile
// Full Definition at https://github.com/yarnpkg/berry/blob/master/packages/yarnpkg-core/sources/Manifest.ts
// Only a subset of full definition are written to the lockfile
type BerryLockfileEntry struct {
	// TODO figure out ordering for these
	// resolved version for the particular entry based on the provided semver revision
	Version      string `yaml:"version"`
	LanguageName string `yaml:"languageName,omitempty"`

	Dependencies     map[string]string `yaml:"dependencies,omitempty"`
	PeerDependencies map[string]string `yaml:"peerDependencies,omitempty"`

	DependenciesMeta     map[string]BerryDependencyMetaEntry `yaml:"dependenciesMeta,omitempty"`
	PeerDependenciesMeta map[string]BerryDependencyMetaEntry `yaml:"peerDependenciesMeta,omitempty"`

	Bin map[string]string `yaml:"bin,omitempty"`

	LinkType   string `yaml:"linkType,omitempty"`
	Resolution string `yaml:"resolution,omitempty"`
	Checksum   string `yaml:"checksum,omitempty"`
	Conditions string `yaml:"conditions,omitempty"`

	// Only used for metadata entry
	CacheKey int `yaml:"cacheKey,omitempty"`
}

// BerryLockfile representation of berry lockfile
type BerryLockfile struct {
	packages map[_Locator]*BerryLockfileEntry
	// might be numbers?
	version  int
	cacheKey int
	// Mapping descriptors (lodash@npm:^4.17.21) to their resolutions (lodash@npm:4.17.21)
	descriptors map[_Descriptor]_Locator
	// Mapping regular package locators to patched package locators
	patches map[_Locator]_Locator
}

// BerryDependencyMetaEntry Structure for holding if a package is optional or not
type BerryDependencyMetaEntry struct {
	Optional bool `yaml:"optional,omitempty"`
}

var _ Lockfile = (*BerryLockfile)(nil)

// ResolvePackage Given a package and version returns the key, resolved version, and if it was found
func (l *BerryLockfile) ResolvePackage(name string, version string) (string, string, bool) {
	for _, key := range berryPossibleKeys(name, version) {
		if locator, ok := l.descriptors[key]; ok {
			entry := l.packages[locator]
			return locator.asString(), entry.Version, true
		}
	}

	return "", "", false
}

// AllDependencies Given a lockfile key return all (dev/optional/peer) dependencies of that package
func (l *BerryLockfile) AllDependencies(key string) (map[string]string, bool) {
	deps := map[string]string{}
	var locator _Locator
	if err := locator.parseLocator(key); err != nil {
		// We should never hit this as we have already vetted all entries in the lockfile
		// during the creation of the lockfile struct
		panic(fmt.Sprintf("invalid locator string: %s", key))
	}
	entry, ok := l.packages[locator]
	if !ok {
		return deps, false
	}

	for name, version := range entry.Dependencies {
		deps[name] = version
	}
	for name, version := range entry.PeerDependencies {
		deps[name] = version
	}

	return deps, true
}

// Subgraph Given a list of lockfile keys returns a Lockfile based off the original one that only contains the packages given
func (l *BerryLockfile) Subgraph(workspacePackages []turbopath.AnchoredSystemPath, packages []string) (Lockfile, error) {
	prunedPackages := make(map[_Locator]*BerryLockfileEntry, len(packages))

	// add root workspace
	for locator, pkg := range l.packages {
		if locator.reference == "workspace:." {
			prunedPackages[locator] = pkg
		}
	}
	// add workspaces
	for _, workspacePackage := range workspacePackages {
		expectedReference := fmt.Sprintf("workspace:%s", workspacePackage.ToString())
		for locator, pkg := range l.packages {
			if locator.reference == expectedReference {
				prunedPackages[locator] = pkg
			}
		}
	}
	for _, key := range packages {
		var locator _Locator
		if err := locator.parseLocator(key); err != nil {
			// We should never hit this as we have already vetted all entries in the lockfile
			// during the creation of the lockfile struct
			panic(fmt.Sprintf("invalid locator string: %s", key))
		}
		entry, ok := l.packages[locator]
		if ok {
			prunedPackages[locator] = entry
		}
		// If a package has a patch it should be included in the subgraph
		patchLocator, ok := l.patches[locator]
		if ok {
			prunedPackages[patchLocator] = l.packages[patchLocator]
		}
	}

	prunedDescriptors := make(map[_Descriptor]_Locator, len(prunedPackages))
	for includedLocator := range prunedPackages {
		for descriptor, locator := range l.descriptors {
			if includedLocator == locator {
				prunedDescriptors[descriptor] = locator
			}
		}
	}

	return &BerryLockfile{
		packages:    prunedPackages,
		version:     l.version,
		cacheKey:    l.cacheKey,
		descriptors: prunedDescriptors,
		patches:     l.patches,
	}, nil
}

// Encode encode the lockfile representation and write it to the given writer
func (l *BerryLockfile) Encode(w io.Writer) error {
	// Map all resolved packages to the descriptors that match them
	reverseLookup := make(map[_Locator]map[_Descriptor]_void, len(l.packages))
	for descriptor, locator := range l.descriptors {
		descriptors, ok := reverseLookup[locator]
		if !ok {
			reverseLookup[locator] = map[_Descriptor]_void{descriptor: {}}
		} else {
			descriptors[descriptor] = _void{}
		}
	}

	lockfile := make(map[string]*BerryLockfileEntry, len(l.packages))

	lockfile[_metadataKey] = &BerryLockfileEntry{
		Version:  fmt.Sprintf("%d", l.version),
		CacheKey: l.cacheKey,
	}

	for locator, descriptors := range reverseLookup {
		sortedDescriptors := make([]string, len(descriptors))
		i := 0
		for descriptor := range descriptors {
			sortedDescriptors[i] = descriptor.asString()
			i++
		}
		sort.Strings(sortedDescriptors)

		key := strings.Join(sortedDescriptors, ", ")

		entry, ok := l.packages[locator]
		if !ok {
			panic(fmt.Sprintf("Unable to find entry for %s", locator.asString()))
		}

		lockfile[key] = entry
	}

	_, err := io.WriteString(w, `# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!
`)
	if err != nil {
		return errors.Wrap(err, "unable to write header to lockfile")
	}

	return _writeBerryLockfile(w, lockfile)
}

// Patches return a list of patches used in the lockfile
func (l *BerryLockfile) Patches() []turbopath.AnchoredUnixPath {
	patches := []turbopath.AnchoredUnixPath{}

	for _, patchLocator := range l.patches {
		patchPath, isPatch := patchLocator.patchPath()

		if isPatch && !strings.HasPrefix(patchPath, "~") && !_builtinRegexp.MatchString(patchPath) {
			patches = append(patches, turbopath.AnchoredUnixPath(patchPath))
		}
	}

	if len(patches) == 0 {
		return nil
	}

	return patches
}

// DecodeBerryLockfile Takes the contents of a berry lockfile and returns a struct representation
func DecodeBerryLockfile(contents []byte) (*BerryLockfile, error) {
	var packages map[string]*BerryLockfileEntry

	err := yaml.Unmarshal(contents, &packages)
	if err != nil {
		return &BerryLockfile{}, fmt.Errorf("could not unmarshal lockfile: %w", err)
	}

	metadata, ok := packages[_metadataKey]
	if !ok {
		return nil, errors.New("No __metadata entry found when decoding yarn.lock")
	}
	version, err := strconv.Atoi(metadata.Version)
	if err != nil {
		return nil, errors.Wrap(err, "yarn lockfile version isn't valid integer")
	}
	delete(packages, _metadataKey)

	locatorToPackage := map[_Locator]*BerryLockfileEntry{}
	descriptorToLocator := map[_Descriptor]_Locator{}
	// A map from packages to their patch entries
	patches := map[_Locator]_Locator{}

	for key, data := range packages {
		var locator _Locator
		if err := locator.parseLocator(data.Resolution); err != nil {
			return nil, errors.Wrap(err, "unable to parse entry")
		}

		if _, isPatch := locator.patchPath(); isPatch {
			// A patch will have the same identifier and version allowing us to construct the non-patch entry
			originalLocator := _Locator{locator._Ident, fmt.Sprintf("npm:%s", data.Version)}
			patches[originalLocator] = locator
		}

		// Before storing cacheKey set it to -1 so we know it's invalid
		data.CacheKey = -1

		locatorToPackage[locator] = data

		// All descriptors that resolve to a single locator are grouped into a single key
		for _, entry := range _multipleKeyRegex.Split(key, -1) {
			descriptor := _Descriptor{}
			if err := descriptor.parseDescriptor(entry); err != nil {
				return nil, errors.Wrap(err, "Bad entry key found")
			}

			// Before lockfile version 6 descriptors could be missing the npm protocol
			if version <= 6 && descriptor.versionRange != "*" {
				_, err := semver.NewConstraint(descriptor.versionRange)
				if err == nil || _tagRegex.MatchString(descriptor.versionRange) {
					descriptor.versionRange = fmt.Sprintf("npm:%s", descriptor.versionRange)
				}
			}

			descriptorToLocator[descriptor] = locator
		}
	}

	lockfile := BerryLockfile{
		packages:    locatorToPackage,
		version:     version,
		cacheKey:    metadata.CacheKey,
		descriptors: descriptorToLocator,
		patches:     patches,
	}
	return &lockfile, nil
}

// Fields shared between _Locator and _Descriptor
type _Ident struct {
	// Scope of package without leading @
	scope string
	// Name of package
	name string
}

type _Locator struct {
	_Ident
	// Resolved version e.g. 1.2.3
	reference string
}

type _Descriptor struct {
	_Ident
	// Version range e.g. ^1.0.0
	versionRange string
}

var _locatorRegexp = regexp.MustCompile("^(?:@([^/]+?)/)?([^/]+?)(?:@(.+))$")

func (l *_Locator) parseLocator(data string) error {
	matches := _locatorRegexp.FindStringSubmatch(data)
	if len(matches) != 4 {
		return fmt.Errorf("%s is not a valid locator string", data)
	}
	l.scope = matches[1]
	l.name = matches[2]
	l.reference = matches[3]

	return nil
}

func (l *_Locator) asString() string {
	if l.scope == "" {
		return fmt.Sprintf("%s@%s", l.name, l.reference)
	}
	return fmt.Sprintf("@%s/%s@%s", l.scope, l.name, l.reference)
}

var _builtinRegexp = regexp.MustCompile("^builtin<([^>]+)>$")

func (l *_Locator) patchPath() (string, bool) {
	if strings.HasPrefix(l.reference, "patch:") {
		patchFileIndex := strings.Index(l.reference, "#")
		paramIndex := strings.LastIndex(l.reference, "::")
		if patchFileIndex == -1 || paramIndex == -1 {
			// Better error handling
			panic("Unable to extract patch file path from lockfile entry")
		}
		patchPath := strings.TrimPrefix(l.reference[patchFileIndex+1:paramIndex], "./")

		return patchPath, true
	}

	return "", false
}

var _descriptorRegexp = regexp.MustCompile("^(?:@([^/]+?)/)?([^/]+?)(?:@(.+))?$")

func (d *_Descriptor) parseDescriptor(data string) error {
	matches := _descriptorRegexp.FindStringSubmatch(data)
	if len(matches) != 4 {
		return fmt.Errorf("%s is not a valid descriptor string", data)
	}

	d.scope = matches[1]
	d.name = matches[2]
	d.versionRange = matches[3]

	return nil
}

func (d *_Descriptor) asString() string {
	if d.scope == "" {
		return fmt.Sprintf("%s@%s", d.name, d.versionRange)
	}
	return fmt.Sprintf("@%s/%s@%s", d.scope, d.name, d.versionRange)
}

func berryPossibleKeys(name string, version string) []_Descriptor {
	makeDescriptor := func(protocol string) _Descriptor {
		descriptorString := fmt.Sprintf("%s@%s%s", name, protocol, version)
		var descriptor _Descriptor
		if err := descriptor.parseDescriptor(descriptorString); err != nil {
			panic("Generated invalid descriptor")
		}
		return descriptor
	}
	return []_Descriptor{
		makeDescriptor(""),
		makeDescriptor("npm:"),
		makeDescriptor("file:"),
		makeDescriptor("workspace:"),
		makeDescriptor("yarn:"),
	}
}

func _writeBerryLockfile(w io.Writer, lockfile map[string]*BerryLockfileEntry) error {
	keys := make([]string, len(lockfile))
	i := 0
	for key := range lockfile {
		keys[i] = key
		i++
	}

	// The __metadata key gets hoisted to the top
	sort.Slice(keys, func(i, j int) bool {
		if keys[i] == _metadataKey {
			return true
		} else if keys[j] == _metadataKey {
			return false
		}
		return keys[i] < keys[j]
	})

	for _, key := range keys {
		value, ok := lockfile[key]
		if !ok {
			panic(fmt.Sprintf("Unable to find entry for %s", key))
		}

		wrappedKey := _wrapString(key)
		wrappedValue := _stringifyEntry(*value, 1)

		var keyPart string
		if len(wrappedKey) > 1024 {
			keyPart = fmt.Sprintf("? %s\n:", keyPart)
		} else {
			keyPart = fmt.Sprintf("%s:", wrappedKey)
		}

		_, err := io.WriteString(w, fmt.Sprintf("\n%s\n%s\n", keyPart, wrappedValue))
		if err != nil {
			return errors.Wrap(err, "unable to write to lockfile")
		}
	}

	return nil
}

var _simpleStringPattern = regexp.MustCompile("^[^-?:,\\][{}#&*!|>'\"%@` \t\r\n]([ \t]*[^,\\][{}:# \t\r\n])*$")

func _wrapString(str string) string {
	if !_simpleStringPattern.MatchString(str) {
		var b bytes.Buffer
		encoder := json.NewEncoder(&b)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(str)
		if err != nil {
			panic("Unexpected error wrapping key")
		}

		return strings.TrimRight(b.String(), "\n")
	}
	return str
}

func _stringifyEntry(entry BerryLockfileEntry, indentLevel int) string {
	lines := []string{}
	addLine := func(field, value string, inline bool) {
		var line string
		if inline {
			line = fmt.Sprintf("  %s: %s", field, value)
		} else {
			line = fmt.Sprintf("  %s:\n%s", field, value)
		}
		lines = append(lines, line)
	}

	if entry.Version != "" {
		addLine("version", _wrapString(entry.Version), true)
	}
	if entry.Resolution != "" {
		addLine("resolution", _wrapString(entry.Resolution), true)
	}
	if len(entry.Dependencies) > 0 {
		addLine("dependencies", _stringifyDeps(entry.Dependencies), false)
	}
	if len(entry.PeerDependencies) > 0 {
		addLine("peerDependencies", _stringifyDeps(entry.PeerDependencies), false)
	}
	if len(entry.DependenciesMeta) > 0 {
		addLine("dependenciesMeta", _stringifyDepsMeta(entry.DependenciesMeta), false)
	}
	if len(entry.PeerDependenciesMeta) > 0 {
		addLine("peerDependenciesMeta", _stringifyDepsMeta(entry.PeerDependenciesMeta), false)
	}

	if len(entry.Bin) > 0 {
		addLine("bin", _stringifyDeps(entry.Bin), false)
	}
	if entry.Checksum != "" {
		addLine("checksum", _wrapString(entry.Checksum), true)
	}
	if entry.Conditions != "" {
		addLine("conditions", _wrapString(entry.Conditions), true)
	}
	if entry.LanguageName != "" {
		addLine("languageName", _wrapString(entry.LanguageName), true)
	}
	if entry.LinkType != "" {
		addLine("linkType", _wrapString(entry.LinkType), true)
	}
	if entry.CacheKey >= 0 {
		addLine("cacheKey", fmt.Sprintf("%d", entry.CacheKey), true)
	}

	return strings.Join(lines, "\n")
}

func _stringifyDeps(deps map[string]string) string {
	keys := make([]string, len(deps))
	i := 0
	for key := range deps {
		keys[i] = key
		i++
	}
	sort.Strings(keys)

	lines := make([]string, 0, len(deps))
	addLine := func(name, version string) {
		lines = append(lines, fmt.Sprintf("    %s: %s", _wrapString(name), _wrapString(version)))
	}

	for _, name := range keys {
		version := deps[name]
		addLine(name, version)
	}

	return strings.Join(lines, "\n")
}

func _stringifyDepsMeta(meta map[string]BerryDependencyMetaEntry) string {
	keys := make([]string, len(meta))
	i := 0
	for key := range meta {
		keys[i] = key
		i++
	}
	sort.Strings(keys)

	lines := make([]string, 0, len(meta))
	addLine := func(name string) {
		lines = append(lines, fmt.Sprintf("    %s:\n      optional: true", _wrapString(name)))
	}

	for _, name := range keys {
		optional := meta[name]
		if optional.Optional {
			addLine(name)
		}
	}

	return strings.Join(lines, "\n")
}
