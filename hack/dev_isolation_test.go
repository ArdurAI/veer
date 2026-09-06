package hack

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const seededCredential = "veer-proxy-credential-must-not-leak"

func TestDevelopmentEnvironmentIsBoundToHost(t *testing.T) {
	overrides := map[string]string{
		"GOOS": "plan9", "GOARCH": "386", "GO386": "387", "GOAMD64": "v4",
		"GOARM": "7", "GOARM64": "v9.5", "GOMIPS": "softfloat",
		"GOMIPS64": "softfloat", "GOPPC64": "power10", "GORISCV64": "rva23u64",
		"GOWASM": "satconv", "GOFIPS140": "latest", "GOEXPERIMENT": "fieldtrack",
		"GOHOSTOS": "plan9", "GOHOSTARCH": "386",
		"http_proxy":  "http://user:" + seededCredential + "@proxy.invalid:8080",
		"https_proxy": "http://user:" + seededCredential + "@proxy.invalid:8080",
		"all_proxy":   "socks5://user:" + seededCredential + "@proxy.invalid:1080",
		"HTTP_PROXY":  "http://user:" + seededCredential + "@proxy.invalid:8080",
		"HTTPS_PROXY": "http://user:" + seededCredential + "@proxy.invalid:8080",
		"ALL_PROXY":   "socks5://user:" + seededCredential + "@proxy.invalid:1080",
		"NO_PROXY":    "internal.invalid", "no_proxy": "internal.invalid",
		"GIT_DIR": "/redirected/repository", "GIT_WORK_TREE": "/redirected/worktree",
		"GIT_COMMON_DIR": "/redirected/common", "GIT_INDEX_FILE": "/redirected/index",
		"GIT_OBJECT_DIRECTORY":             "/redirected/objects",
		"GIT_ALTERNATE_OBJECT_DIRECTORIES": "/redirected/alternate",
		"GIT_NAMESPACE":                    "redirected", "GIT_CEILING_DIRECTORIES": "/",
		"GIT_DISCOVERY_ACROSS_FILESYSTEM": "1", "GIT_PREFIX": "redirected/",
		"GIT_CONFIG_SYSTEM": "/redirected/system-config",
		"GIT_CONFIG_GLOBAL": "/redirected/global-config", "GIT_CONFIG_NOSYSTEM": "0",
		"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_PARAMETERS": "'core.bare=true'",
		"GIT_EXEC_PATH": "/redirected/exec-path",
	}
	output, err := runDevelopmentCommand(t, overrides, "_test-isolation")
	if bytes.Contains(output, []byte(seededCredential)) {
		t.Fatal("isolation probe exposed the seeded proxy credential")
	}
	if err != nil {
		t.Fatalf("isolation probe failed: %v\n%s", err, redactSeededCredential(output))
	}

	want := fmt.Sprintf(
		"veer-isolation target_os=%s target_arch=%s architecture_tuning=default proxy=disabled git_selection=isolated\n",
		runtime.GOOS,
		runtime.GOARCH,
	)
	if string(output) != want {
		t.Fatalf("unexpected isolation report: got %q, want %q", output, want)
	}
}

func TestPlatformSelectionCoversSupportedMatrix(t *testing.T) {
	tests := []struct {
		system  string
		machine string
		want    string
	}{
		{system: "Darwin", machine: "x86_64", want: "darwin/amd64\n"},
		{system: "Darwin", machine: "arm64", want: "darwin/arm64\n"},
		{system: "Linux", machine: "amd64", want: "linux/amd64\n"},
		{system: "Linux", machine: "aarch64", want: "linux/arm64\n"},
	}
	for _, test := range tests {
		t.Run(test.system+"-"+test.machine, func(t *testing.T) {
			output, err := runDevelopmentCommand(t, nil, "_test-platform", test.system, test.machine)
			if err != nil {
				t.Fatalf("select platform: %v\n%s", err, output)
			}
			if string(output) != test.want {
				t.Fatalf("unexpected platform: got %q, want %q", output, test.want)
			}
		})
	}
}

func TestSourceDiscoveryIgnoresInheritedGitSelection(t *testing.T) {
	repositoryRoot := developmentRepositoryRoot(t)
	fixtureDirectory, err := os.MkdirTemp(repositoryRoot, "isolation-source-")
	if err != nil {
		t.Fatalf("create untracked source fixture: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(fixtureDirectory); err != nil {
			t.Errorf("remove untracked source fixture: %v", err)
		}
	})
	fixturePath := filepath.Join(fixtureDirectory, "probe.go")
	if err := os.WriteFile(fixturePath, []byte("package probe\n"), 0o600); err != nil {
		t.Fatalf("write untracked source fixture: %v", err)
	}
	fixtureRelative, err := filepath.Rel(repositoryRoot, fixturePath)
	if err != nil {
		t.Fatalf("resolve fixture path: %v", err)
	}

	redirectedRepository := filepath.Join(t.TempDir(), "redirected.git")
	initCommand := exec.Command("git", "init", "--bare", "--quiet", redirectedRepository)
	if output, err := initCommand.CombinedOutput(); err != nil {
		t.Fatalf("create redirected Git repository: %v\n%s", err, output)
	}
	excludeFile := filepath.Join(t.TempDir(), "global-excludes")
	if err := os.WriteFile(excludeFile, []byte("*.go\n"), 0o600); err != nil {
		t.Fatalf("write hostile global excludes: %v", err)
	}
	overrides := map[string]string{
		"GIT_DIR":                          redirectedRepository,
		"GIT_WORK_TREE":                    t.TempDir(),
		"GIT_INDEX_FILE":                   filepath.Join(t.TempDir(), "redirected-index"),
		"GIT_OBJECT_DIRECTORY":             filepath.Join(t.TempDir(), "redirected-objects"),
		"GIT_ALTERNATE_OBJECT_DIRECTORIES": filepath.Join(t.TempDir(), "alternate-objects"),
		"GIT_COMMON_DIR":                   redirectedRepository,
		"GIT_CEILING_DIRECTORIES":          repositoryRoot,
		"GIT_DISCOVERY_ACROSS_FILESYSTEM":  "1",
		"GIT_NAMESPACE":                    "redirected",
		"GIT_CONFIG_COUNT":                 "1",
		"GIT_CONFIG_KEY_0":                 "core.excludesFile",
		"GIT_CONFIG_VALUE_0":               excludeFile,
	}
	output, err := runDevelopmentCommand(t, overrides, "_test-go-sources")
	if err != nil {
		t.Fatalf("isolated source discovery: %v\n%s", err, output)
	}

	paths := strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00")
	if !containsString(paths, "hack/dev_isolation_test.go") {
		t.Fatalf("tracked source disappeared under inherited Git state: %q", paths)
	}
	if !containsString(paths, fixtureRelative) {
		t.Fatalf("untracked source was suppressed by inherited Git config: %q", paths)
	}
}

func TestSourceDiscoveryDoesNotMaskGitFailure(t *testing.T) {
	fakeDirectory := t.TempDir()
	fakeGit := filepath.Join(fakeDirectory, "git")
	fakeGitScript := `#!/bin/sh
repository_root=
previous=
for argument do
	if [ "$previous" = -C ]; then
		repository_root=$argument
	fi
	previous=$argument
done
case " $* " in
	*" rev-parse --show-toplevel "*)
		printf '%s\n' "$repository_root"
		exit 0
		;;
	*" ls-files "*) exit 23 ;;
	*) exit 24 ;;
esac
`
	if err := os.WriteFile(fakeGit, []byte(fakeGitScript), 0o700); err != nil {
		t.Fatalf("write failing Git fixture: %v", err)
	}
	overrides := map[string]string{
		"PATH":   fakeDirectory + string(os.PathListSeparator) + os.Getenv("PATH"),
		"TMPDIR": t.TempDir(),
	}
	output, err := runDevelopmentCommand(t, overrides, "_test-go-sources")
	if err == nil {
		t.Fatalf("failed Git source enumeration was masked: %q", output)
	}
	if !bytes.Contains(output, []byte("cannot enumerate go source files")) {
		t.Fatalf("missing Git producer-failure diagnostic: %s", output)
	}
}

func TestSourceFilterRejectsSymbolicLinkComponents(t *testing.T) {
	repositoryRoot := t.TempDir()
	physicalRepositoryRoot, err := filepath.EvalSymlinks(repositoryRoot)
	if err != nil {
		t.Fatalf("resolve physical repository fixture: %v", err)
	}
	repositoryRoot = physicalRepositoryRoot
	outsideDirectory := t.TempDir()
	outsideSource := filepath.Join(outsideDirectory, "probe.go")
	original := []byte("package outside\n")
	if err := os.WriteFile(outsideSource, original, 0o600); err != nil {
		t.Fatalf("write outside source: %v", err)
	}
	if err := os.Symlink(outsideDirectory, filepath.Join(repositoryRoot, "source")); err != nil {
		t.Fatalf("create parent symlink: %v", err)
	}

	filter := filepath.Join(developmentRepositoryRoot(t), "hack", "filter-source-files")
	command := exec.Command("sh", filter, repositoryRoot, "source/probe.go")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("source below a parent symlink unexpectedly passed: %q", output)
	}
	if !bytes.Contains(output, []byte("source path contains a symbolic-link component")) {
		t.Fatalf("missing symlink rejection diagnostic: %s", output)
	}
	after, err := os.ReadFile(outsideSource)
	if err != nil {
		t.Fatalf("read outside source: %v", err)
	}
	if !bytes.Equal(after, original) {
		t.Fatal("outside source changed during validation")
	}
}

func TestBootstrapPrerequisitesAreDocumented(t *testing.T) {
	want := []string{
		"awk", "cat", "chmod", "cp", "curl", "date", "diff", "dirname", "env",
		"git", "grep", "head", "ln", "mkdir", "mktemp", "mv", "pwd", "rm",
		"sed", "sort", "tar", "uname", "wc", "xargs",
	}
	root := developmentRepositoryRoot(t)
	script, err := os.ReadFile(filepath.Join(root, "hack", "dev"))
	if err != nil {
		t.Fatalf("read development script: %v", err)
	}
	marker := []byte("bootstrap_host_commands='")
	start := bytes.Index(script, marker)
	if start < 0 {
		t.Fatal("development script has no bootstrap prerequisite declaration")
	}
	start += len(marker)
	end := bytes.IndexByte(script[start:], '\'')
	if end < 0 {
		t.Fatal("bootstrap prerequisite declaration is unterminated")
	}
	got := strings.Fields(string(script[start : start+end]))
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("unexpected bootstrap prerequisites: got %q, want %q", got, want)
	}

	documentation, err := os.ReadFile(filepath.Join(root, "docs", "development.md"))
	if err != nil {
		t.Fatalf("read development documentation: %v", err)
	}
	for _, command := range want {
		if !bytes.Contains(documentation, []byte("`"+command+"`")) {
			t.Errorf("development documentation is missing prerequisite %q", command)
		}
	}
	for _, checksumCommand := range []string{"shasum", "sha256sum"} {
		if !bytes.Contains(documentation, []byte("`"+checksumCommand+"`")) {
			t.Errorf("development documentation is missing checksum alternative %q", checksumCommand)
		}
	}
}

func runDevelopmentCommand(t *testing.T, overrides map[string]string, arguments ...string) ([]byte, error) {
	t.Helper()
	root := developmentRepositoryRoot(t)
	command := exec.Command("sh", append([]string{filepath.Join(root, "hack", "dev")}, arguments...)...)
	command.Dir = root
	command.Env = environmentWithOverrides(overrides)
	return command.CombinedOutput()
}

func environmentWithOverrides(overrides map[string]string) []string {
	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if _, replaced := overrides[name]; !replaced {
			environment = append(environment, entry)
		}
	}
	names := make([]string, 0, len(overrides))
	for name := range overrides {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		environment = append(environment, name+"="+overrides[name])
	}
	return environment
}

func developmentRepositoryRoot(t *testing.T) string {
	t.Helper()
	packageDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("resolve package working directory: %v", err)
	}
	return filepath.Dir(packageDirectory)
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func redactSeededCredential(output []byte) []byte {
	return bytes.ReplaceAll(output, []byte(seededCredential), []byte("[REDACTED]"))
}
