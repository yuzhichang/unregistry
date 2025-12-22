package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const VERSION = "0.4.1"

var (
	startTime      = time.Now()
	help           = flag.Bool("h", false, "Show help")
	version        = flag.Bool("version", false, "Show version")
	verbose        = flag.Bool("verbose", false, "Verbose output")
	pull           = flag.Bool("pull", false, "Pull mode")
	sshKey         = flag.String("i", "", "Path to SSH private key")
	noHostKeyCheck = flag.Bool("no-host-key-check", false, "Skip SSH host key checking")
	platform       = flag.String("platform", "", "Push a specific platform for multi-platform images")
	cachedSSHArgs  []string
	imgName        string
	imgNamespace   string
	remoteHost     string
	sshTunnel      *exec.Cmd
	unregContainer string
)

var containerdSocketPaths = []string{
	"/run/containerd/containerd.sock",
	"/var/run/containerd/containerd.sock",
	"/run/docker/containerd/containerd.sock",
	"/var/run/docker/containerd/containerd.sock",
	"/run/snap.docker/containerd/containerd.sock",
}

var toolDirectories = []string{
	".",
	".local/bin/",
	"/usr/local/bin/",
	"/usr/bin/",
	"/usr/sbin/",
	"/opt/docker/bin/",
	"/snap/bin/",
	"/storage/.docker/bin",
}

type ToolInfo struct {
	IsRemote bool
	Name     string
	Path     string
	Sudo     string
	Socket   string
}

var toolInfos = []ToolInfo{
	{IsRemote: false},
	{IsRemote: true},
}

func getToolInfo(isRemote bool) *ToolInfo {
	for i := range len(toolInfos) {
		if toolInfos[i].IsRemote == isRemote {
			return &toolInfos[i]
		}
	}
	return nil
}

func getHostname(isRemote bool) string {
	if isRemote {
		return remoteHost
	}
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "local"
}

var unregImage = func() string {
	if img := os.Getenv("UNREGISTRY_IMAGE"); img != "" {
		return img
	}
	return "ghcr.io/psviderski/unregistry:0.4.1"
}()

// --- SSH Helpers ---

func buildSSHArgs() []string {
	args := []string{}
	if *sshKey != "" {
		args = append(args, "-i", *sshKey)
	}
	if *noHostKeyCheck {
		args = append(args, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null")
	}
	args = append(args, remoteHost)
	return args
}

// --- Logging Helpers ---

func logPrintf(level, format string, v ...any) {
	elapsed := int(time.Since(startTime).Seconds())
	prefix := fmt.Sprintf("%-4s[%04d] ", level, elapsed)
	fmt.Fprintf(os.Stderr, prefix+format+"\n", v...)
}

func info(format string, v ...any) { logPrintf("INFO", format, v...) }

func debug(format string, v ...any) {
	if *verbose {
		logPrintf("DEBU", format, v...)
	}
}

// --- Path and Socket Helpers ---

func findContainerdSocket(isRemote bool) (string, string) {
	for _, p := range containerdSocketPaths {
		testCmd := fmt.Sprintf("test -S %s", p)
		debug("Testing socket path: %s", p)
		if isRemote {
			sshArgs := make([]string, len(cachedSSHArgs))
			copy(sshArgs, cachedSSHArgs)
			sshArgs = append(sshArgs, testCmd)
			if exec.Command("ssh", sshArgs...).Run() == nil {
				return p, ""
			}
			sshArgsSudo := make([]string, len(cachedSSHArgs))
			copy(sshArgsSudo, cachedSSHArgs)
			sshArgsSudo = append(sshArgsSudo, "sudo -n "+testCmd)
			if exec.Command("ssh", sshArgsSudo...).Run() == nil {
				return p, "sudo -n"
			}
		} else {
			if exec.Command("sh", "-c", testCmd).Run() == nil {
				return p, ""
			}
			if exec.Command("sh", "-c", "sudo -n "+testCmd).Run() == nil {
				return p, "sudo -n"
			}
		}
	}
	return "", ""
}

// --- Command String Builders ---

func buildToolCmd(isRemote bool, ns string, args ...string) (string, []string) {
	var parts []string
	toolInfo := getToolInfo(isRemote)
	if toolInfo == nil {
		return "", nil
	}
	if toolInfo.Sudo != "" {
		parts = append(parts, toolInfo.Sudo)
	}
	parts = append(parts, toolInfo.Path)
	if toolInfo.Name != "docker" {
		if toolInfo.Socket != "" {
			parts = append(parts, "--address", toolInfo.Socket)
		}
		if ns != "" {
			parts = append(parts, "--namespace", ns)
		}
	}
	parts = append(parts, args...)
	shellCmd := strings.Join(parts, " ")
	var cmd string
	var args2 []string
	if isRemote {
		cmd = "ssh"
		args2 = make([]string, len(cachedSSHArgs))
		copy(args2, cachedSSHArgs)
		args2 = append(args2, shellCmd)
	} else {
		cmd = "bash"
		args2 = []string{"-c", shellCmd}
	}
	info("Executing: %s %q", cmd, args2)
	return cmd, args2
}

// --- Logic Helpers ---

func runCmdWithLiveOutput(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func checkImageExists(isRemote bool, image string) bool {
	cmd, args := buildToolCmd(isRemote, "", "image", "inspect", image)
	return exec.Command(cmd, args...).Run() == nil
}

func listNamespaces(isRemote bool) ([]string, error) {
	cmd, args := buildToolCmd(isRemote, "", "namespace", "ls")
	output, err := exec.Command(cmd, args...).Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var namespaces []string
	for i, line := range lines {
		if i == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			namespaces = append(namespaces, fields[0])
		}
	}
	return namespaces, nil
}

// findImage finds an image in nerdctl namespaces, falling back to docker if not found.
func findImage(isRemote bool, name, preferNamespace string) (string, error) {
	hostname := getHostname(isRemote)
	info(fmt.Sprintf("Detecting sender(%s) environment...", hostname))
	toolInfo := getToolInfo(isRemote)
	toolInfo.Socket, _ = findContainerdSocket(isRemote)
	for _, toolName := range []string{"nerdctl", "docker"} {
		if tool, toolSudo, err := checkTool(isRemote, toolName, toolInfo.Socket); err == nil {
			toolInfo.Name = toolName
			toolInfo.Path, toolInfo.Sudo = tool, toolSudo
			info("%s tool: %s (sudo: %v), socket: %s", hostname, toolInfo.Path, toolInfo.Sudo != "", toolInfo.Socket)
			break
		}
	}
	if toolInfo.Name == "" {
		return "", fmt.Errorf("%s: neither nerdctl nor docker works!", hostname)
	}

	if toolInfo.Name == "nerdctl" {
		namespaces, err := listNamespaces(isRemote)
		if err != nil {
			return "", err
		}
		var targetNS []string
		for _, ns := range namespaces {
			if ns == preferNamespace {
				targetNS = append([]string{ns}, targetNS...)
			} else {
				targetNS = append(targetNS, ns)
			}
		}

		for _, ns := range targetNS {
			cmd, args := buildToolCmd(isRemote, ns, "image", "inspect", name)
			if exec.Command(cmd, args...).Run() == nil {
				info(fmt.Sprintf("%s image '%s' found in namespace '%s' in nerdctl", hostname, name, ns))
				return ns, nil
			}
		}

		info(fmt.Sprintf("%s switching to docker", hostname))
		if tool, toolSudo, err := checkTool(isRemote, "docker", toolInfo.Socket); err != nil {
			return "", err
		} else {
			toolInfo.Name = "docker"
			toolInfo.Path, toolInfo.Sudo = tool, toolSudo
			info("%s tool: %s (sudo: %v), socket: %s", hostname, toolInfo.Path, toolInfo.Sudo != "", toolInfo.Socket)
		}
	}
	if checkImageExists(isRemote, name) {
		return "", nil
	}
	info(fmt.Sprintf("%s image '%s' not found in docker", hostname, name))
	return "", fmt.Errorf("%s image '%s' not found in Docker", hostname, name)
}

// --- Infrastructure ---

// transferunregImage transfers unregistry image to remote host via SCP.
func transferunregImage() error {
	if !checkImageExists(false, unregImage) {
		info("Unregistry image not found locally, pulling...")
		cmd, args := buildToolCmd(false, "", "pull", unregImage)
		if err := runCmdWithLiveOutput(cmd, args...); err != nil {
			return fmt.Errorf("failed to pull unregistry image locally: %w", err)
		}
	}

	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("unreg-%d.tar", time.Now().Unix()))
	info("Exporting unregistry image to %s...", tempFile)
	cmd, args := buildToolCmd(false, "", "save", "-o", tempFile, unregImage)
	if err := runCmdWithLiveOutput(cmd, args...); err != nil {
		return fmt.Errorf("failed to export unregistry image: %w", err)
	}
	defer os.Remove(tempFile)

	remoteFile := fmt.Sprintf("/tmp/unreg-%d.tar", time.Now().Unix())
	info("Transferring unregistry image to remote via SCP...")
	scpArgs := []string{tempFile, remoteHost + ":" + remoteFile}
	if *sshKey != "" {
		scpArgs = append([]string{"-i", *sshKey}, scpArgs...)
	}
	if err := runCmdWithLiveOutput("scp", scpArgs...); err != nil {
		return fmt.Errorf("failed to transfer image via SCP: %w", err)
	}

	info("Loading unregistry image on remote...")
	cmd, args = buildToolCmd(true, "", "load", "-i", remoteFile)
	if err := runCmdWithLiveOutput(cmd, args...); err != nil {
		return fmt.Errorf("failed to load unregistry image on remote: %w", err)
	}
	if err := runCmdWithLiveOutput("ssh", remoteHost, "rm -f "+remoteFile); err != nil {
		return fmt.Errorf("failed to remove remote file %s: %w", remoteFile, err)
	}
	return nil
}

// isPortAvailable checks if a local TCP port is available.
func isPortAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// forwardPort establishes SSH tunnel to given remote port, returns local port.
func forwardPort(remotePort int) (int, error) {
	for attempt := 0; attempt < 10; attempt++ {
		localPort := 55000 + int(time.Now().UnixNano()%10536)

		// Check if port is already in use locally
		if !isPortAvailable(localPort) {
			continue
		}

		info("Establishing SSH tunnel: local:%d -> remote:%d", localPort, remotePort)
		sshArgs := make([]string, len(cachedSSHArgs))
		copy(sshArgs, cachedSSHArgs)
		sshArgs = append(sshArgs, "-L", fmt.Sprintf("%d:127.0.0.1:%d", localPort, remotePort), "-N")
		cmd := exec.Command("ssh", sshArgs...)
		sshTunnel = cmd
		if err := cmd.Start(); err != nil {
			// If SSH fails to start, try another port
			continue
		}

		// Try to connect to the local port to verify tunnel is up
		for i := 0; i < 40; i++ {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), 500*time.Millisecond)
			if err == nil {
				conn.Close()
				return localPort, nil
			}
			time.Sleep(250 * time.Millisecond)
		}

		// Tunnel failed to establish, kill the process and try another port
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}
	return 0, fmt.Errorf("failed to find an available local port to forward to remote unregistry port")
}

// startUnregistry starts unregistry container on remote host.
func startUnregistry(ns string) (int, error) {
	// Ensure unregistry image exists on remote host before attempting to start container
	if !checkImageExists(true, unregImage) {
		if err := transferunregImage(); err != nil {
			return 0, err
		}
	}

	if ns == "" {
		ns = "moby"
	}
	for attempt := 0; attempt < 10; attempt++ {
		port := 55000 + int(time.Now().UnixNano()%10536)
		unregContainer = fmt.Sprintf("unreg-pussh-%d-%d", time.Now().Unix(), port)
		toolInfo := getToolInfo(true)

		info("Starting unregistry container '%s' on remote port %d...", unregContainer, port)
		cmd, args := buildToolCmd(true, "", "run", "-d", "--name", unregContainer, "-v", fmt.Sprintf("%s:/run/containerd/containerd.sock", toolInfo.Socket), "--net", "host", "--userns=host", "--user", "root:root", unregImage, "--addr", fmt.Sprintf("127.0.0.1:%d", port), "--namespace", ns)

		// Run command and capture output to check for port binding errors
		cmdObj := exec.Command(cmd, args...)
		var stderr bytes.Buffer
		cmdObj.Stderr = &stderr
		if err := cmdObj.Run(); err != nil {
			output := stderr.String()
			// Remove the container that failed to start if it was created
			cleanupCmd, cleanupArgs := buildToolCmd(true, "", "rm", "-f", unregContainer)
			exec.Command(cleanupCmd, cleanupArgs...).Run()

			// Check if the error is due to port binding
			if strings.Contains(strings.ToLower(output), "bind") {
				// Port binding conflict, try another port
				continue
			}
			return 0, fmt.Errorf("failed to start unregistry container: %w\n%s", err, output)
		}
		return port, nil
	}
	return 0, fmt.Errorf("failed to start unregistry container after 10 attempts due to port binding conflicts")
}

// cleanup cleans up SSH tunnel and remote unregistry container.
func cleanup() {
	info("Cleaning up tunnel and remote container...")
	if sshTunnel != nil && sshTunnel.Process != nil {
		_ = sshTunnel.Process.Kill()
	}
	if unregContainer != "" {
		cmd, args := buildToolCmd(true, "", "rm", "-f", unregContainer)
		if err := runCmdWithLiveOutput(cmd, args...); err != nil {
			logPrintf("WARN", "Failed to remove unregistry container '%s': %v", unregContainer, err)
		}
	}
}

// --- Handlers ---

// handlePush pushes an image from local to remote.
func handlePush() error {
	hostname := getHostname(true)
	info("Detecting receiver(%s) environment...", hostname)
	toolInfo := getToolInfo(true)
	toolInfo.Socket, _ = findContainerdSocket(true)
	toolName := "nerdctl"
	if imgNamespace == "" {
		toolName = "docker"
	}

	if tool, toolSudo, err := checkTool(true, toolName, toolInfo.Socket); err != nil {
		return err
	} else {
		toolInfo.Name = toolName
		toolInfo.Path = tool
		toolInfo.Sudo = toolSudo
		info("%s tool: %s (sudo: %v), socket: %s", hostname, toolInfo.Path, toolInfo.Sudo != "", toolInfo.Socket)
	}

	foundNs, err := findImage(false, imgName, imgNamespace)
	if err != nil {
		return err
	}

	rPort, err := startUnregistry(imgNamespace)
	if err != nil {
		return err
	}

	lPort, err := forwardPort(rPort)
	if err != nil {
		return err
	}

	localTag := fmt.Sprintf("localhost:%d/%s", lPort, imgName)
	remoteTag := fmt.Sprintf("localhost:%d/%s", rPort, imgName)

	info("Local - pushing image '%s' to registry via tunnel...", imgName)
	cmd, args := buildToolCmd(false, foundNs, "tag", imgName, localTag)
	if err := runCmdWithLiveOutput(cmd, args...); err != nil {
		return fmt.Errorf("local tag failed: %w", err)
	}

	pushArgs := []string{"push", "--quiet"}
	if *platform != "" {
		pushArgs = append(pushArgs, "--platform", *platform)
	}
	pushArgs = append(pushArgs, localTag)
	cmd, args = buildToolCmd(false, foundNs, pushArgs...)
	if err := runCmdWithLiveOutput(cmd, args...); err != nil {
		return fmt.Errorf("local push failed: %w", err)
	}

	cmd, args = buildToolCmd(false, foundNs, "rmi", localTag)
	if err := runCmdWithLiveOutput(cmd, args...); err != nil {
		return fmt.Errorf("local rmi failed: %w", err)
	}

	// The tag/rmi workflow can be bypassed to save approximately 1s if the containerd.snapshotter mechanism is enabled.
	// Note that unlike "docker info", "nerdctl info" provides no reliable way to detect this state.
	info("Remote - pulling image '%s' from registry...", imgName)
	pullArgs := []string{"pull", "--quiet"}
	if *platform != "" {
		pullArgs = append(pullArgs, "--platform", *platform)
	}
	pullArgs = append(pullArgs, remoteTag)
	cmd, args = buildToolCmd(true, imgNamespace, pullArgs...)
	if err := runCmdWithLiveOutput(cmd, args...); err != nil {
		return fmt.Errorf("remote pull failed: %w", err)
	}

	cmd, args = buildToolCmd(true, imgNamespace, "tag", remoteTag, imgName)
	if err := runCmdWithLiveOutput(cmd, args...); err != nil {
		return fmt.Errorf("remote tag failed: %w", err)
	}

	cmd, args = buildToolCmd(true, imgNamespace, "rmi", remoteTag)
	if err := runCmdWithLiveOutput(cmd, args...); err != nil {
		return fmt.Errorf("remote rmi failed: %w", err)
	}
	info("Push successful.")
	return nil
}

// handlePull pulls an image from remote to local.
func handlePull() error {
	hostname := getHostname(false)
	info("Detecting receiver(%s) environment...", hostname)
	toolInfo := getToolInfo(false)
	toolInfo.Socket, _ = findContainerdSocket(false)
	toolName := "nerdctl"
	if imgNamespace == "" {
		toolName = "docker"
	}

	if tool, toolSudo, err := checkTool(false, toolName, toolInfo.Socket); err != nil {
		return err
	} else {
		toolInfo.Name = toolName
		toolInfo.Path = tool
		toolInfo.Sudo = toolSudo
		info("%s tool: %s (sudo: %v), socket: %s", hostname, toolInfo.Path, toolInfo.Sudo != "", toolInfo.Socket)
	}

	foundNs, err := findImage(true, imgName, imgNamespace)
	if err != nil {
		return err
	}

	rPort, err := startUnregistry(foundNs)
	if err != nil {
		return err
	}

	lPort, err := forwardPort(rPort)
	if err != nil {
		return err
	}

	localTag := fmt.Sprintf("localhost:%d/%s", lPort, imgName)
	remoteTag := fmt.Sprintf("localhost:%d/%s", rPort, imgName)

	info("Remote - pushing image '%s' to registry...", imgName)
	cmd, args := buildToolCmd(true, foundNs, "tag", imgName, remoteTag)
	if err := runCmdWithLiveOutput(cmd, args...); err != nil {
		return fmt.Errorf("remote tag failed: %w", err)
	}

	pushArgs := []string{"push", "--quiet"}
	if *platform != "" {
		pushArgs = append(pushArgs, "--platform", *platform)
	}
	pushArgs = append(pushArgs, remoteTag)
	cmd, args = buildToolCmd(true, foundNs, pushArgs...)
	if err := runCmdWithLiveOutput(cmd, args...); err != nil {
		return fmt.Errorf("remote push failed: %w", err)
	}

	cmd, args = buildToolCmd(true, foundNs, "rmi", remoteTag)
	if err := runCmdWithLiveOutput(cmd, args...); err != nil {
		return fmt.Errorf("remote rmi failed: %w", err)
	}

	info("Local - pulling image '%s' from registry via tunnel...", imgName)
	pullArgs := []string{"pull", "--quiet"}
	if *platform != "" {
		pullArgs = append(pullArgs, "--platform", *platform)
	}
	pullArgs = append(pullArgs, localTag)
	cmd, args = buildToolCmd(false, imgNamespace, pullArgs...)
	if err := runCmdWithLiveOutput(cmd, args...); err != nil {
		return fmt.Errorf("local pull failed: %w", err)
	}

	cmd, args = buildToolCmd(false, imgNamespace, "tag", localTag, imgName)
	if err := runCmdWithLiveOutput(cmd, args...); err != nil {
		return fmt.Errorf("local tag failed: %w", err)
	}

	cmd, args = buildToolCmd(false, imgNamespace, "rmi", localTag)
	if err := runCmdWithLiveOutput(cmd, args...); err != nil {
		return fmt.Errorf("local rmi failed: %w", err)
	}
	info("Pull successful.")
	return nil
}

// --- Detection ---

// checkTool finds container tool (docker/nerdctl) and required sudo prefix.
func checkTool(isRemote bool, toolName, socket string) (string, string, error) {
	var paths []string
	whichCmd := "which " + toolName
	if out, err := (func() ([]byte, error) {
		if isRemote {
			return exec.Command("ssh", remoteHost, whichCmd).Output()
		}
		return exec.Command("sh", "-c", whichCmd).Output()
	})(); err == nil {
		paths = append(paths, strings.TrimSpace(string(out)))
	}

	for _, dir := range toolDirectories {
		paths = append(paths, filepath.Join(dir, toolName))
	}

	for _, p := range paths {
		testCmd := p + " image ls"
		if toolName != "docker" {
			testCmd += fmt.Sprintf(" --address %s", socket)
		}
		debug("Testing tool path %s", p)
		if isRemote {
			sshArgs := make([]string, len(cachedSSHArgs))
			copy(sshArgs, cachedSSHArgs)
			sshArgs = append(sshArgs, testCmd)
			if exec.Command("ssh", sshArgs...).Run() == nil {
				return p, "", nil
			}
			sshArgsSudo := make([]string, len(cachedSSHArgs))
			copy(sshArgsSudo, cachedSSHArgs)
			sshArgsSudo = append(sshArgsSudo, "sudo -n "+testCmd)
			if exec.Command("ssh", sshArgsSudo...).Run() == nil {
				return p, "sudo -n", nil
			}
		} else {
			if exec.Command("sh", "-c", testCmd).Run() == nil {
				return p, "", nil
			}
			if exec.Command("sh", "-c", "sudo -n "+testCmd).Run() == nil {
				return p, "sudo -n", nil
			}
		}
	}
	return "", "", fmt.Errorf("tool '%s' not found or accessible", toolName)
}

// run is the main entry point after flag parsing.
func run() error {
	image, host := flag.Arg(0), flag.Arg(1)
	parts := strings.SplitN(image, "::", 2)
	if len(parts) == 2 {
		imgNamespace, imgName = parts[0], parts[1]
	} else {
		imgNamespace, imgName = "", image
	}
	remoteHost = host
	cachedSSHArgs = buildSSHArgs()

	// Use defer to ensure cleanup happens even if an error occurs later
	defer cleanup()

	if *pull {
		return handlePull()
	}
	return handlePush()
}

func main() {
	flag.Usage = func() {
		fmt.Print(`pussh - Push/pull container images via SSH without external registries.

USAGE: pussh [OPTIONS] IMAGE HOST

IMAGE format:
  - <image>:tag             Sender uses nerdctl to search the image in all namespaces first.
                            If not found in any namespace, sender falls back to docker.
                            Receiver uses docker to store the image.
  - <namespace>::<image>:tag Sender uses nerdctl to search the image in the given namespace first, then other namespaces.
                            If not found in any namespace, sender falls back to docker.
                            Receiver uses nerdctl to store the image in the given namespace.

OPTIONS:
  -h, --help                Show help
  --version                 Show version
  --verbose                 Enable debug logging
  --pull                    Pull mode (remote to local)
  -i, --ssh-key             Path to SSH private key
  --no-host-key-check       Skip SSH host key checking
  --platform                Specify a platform for multi-platform images
`)
	}
	flag.Parse()

	// Ensure localhost connections bypass proxy.
	os.Setenv("no_proxy", os.Getenv("no_proxy")+",localhost,127.0.0.1")

	if *version {
		fmt.Printf("pussh v%s\n", VERSION)
		return
	}
	if *help || flag.NArg() < 2 {
		flag.Usage()
		return
	}

	// Execute core logic and capture errors to ensure defers run
	if err := run(); err != nil {
		logPrintf("FATA", "%v", err)
	}
}
