//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// javaHttpsCheckSource is a Java program that makes an HTTPS GET request and
// verifies the response body is "ok".  It uses HttpsURLConnection which
// relies on the JVM trust store (cacerts), so it will fail when the CA is
// not trusted.
const javaHttpsCheckSource = `import java.io.*;
import java.net.*;
import javax.net.ssl.*;

public class HttpsCheck {
    public static void main(String[] args) throws Exception {
        URL url = new URL(args[0]);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);
        int code = conn.getResponseCode();
        if (code != 200) {
            System.err.println("unexpected status: " + code);
            System.exit(1);
        }
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        reader.close();
        String body = sb.toString().trim();
        if (!"ok".equals(body)) {
            System.err.println("unexpected body: " + body);
            System.exit(1);
        }
    }
}
`

// javaClientImages lists the Java base images to test.
// Covers multiple JVM vendors, Java versions (8/11/17/21),
// OS flavors (Alpine, Ubuntu/Debian), and cacerts formats (JKS for Java 8,
// PKCS12 for Java 9+).
var javaClientImages = []struct {
	name  string
	image string
}{
	// Eclipse Temurin — the primary OpenJDK distribution
	{"temurin-8-jdk-alpine", "eclipse-temurin:8-jdk-alpine"},
	{"temurin-11-jdk-alpine", "eclipse-temurin:11-jdk-alpine"},
	{"temurin-17-jdk-alpine", "eclipse-temurin:17-jdk-alpine"},
	{"temurin-21-jdk-alpine", "eclipse-temurin:21-jdk-alpine"},
	{"temurin-17-jdk-jammy", "eclipse-temurin:17-jdk-jammy"},

	// Amazon Corretto
	{"corretto-17-alpine", "amazoncorretto:17-alpine"},
	{"corretto-21-alpine", "amazoncorretto:21-alpine"},

	// Azul Zulu
	{"zulu-17-alpine", "azul/zulu-openjdk-alpine:17"},

	// IBM Semeru Runtimes
	{"semeru-17-jdk-jammy", "ibm-semeru-runtimes:open-17-jdk-jammy"},
}

func TestKindIntegration_JavaHTTPSWithInjectedCA(t *testing.T) {
	if getenvOr("CAINJEKT_TLS_E2E", "0") != "1" {
		t.Skip("set CAINJEKT_TLS_E2E=1 to run TLS trust E2E test")
	}

	clusterName := getenvOr("CAINJEKT_CLUSTER_NAME", "cainjekt-test-cluster")
	pluginIdx := getenvOr("CAINJEKT_PLUGIN_IDX", fmt.Sprintf("%02d", (time.Now().UnixNano()%90)+10))

	requireCommand(t, "make")
	requireCommand(t, "kind")
	requireCommand(t, "kubectl")
	requireCommand(t, "docker")
	requireDockerAccess(t)

	runCmd(t, 10*time.Minute, "make", "copy-plugin", "CLUSTER_NAME="+clusterName)
	node := strings.TrimSpace(runCmd(t, 30*time.Second, "kind", "get", "nodes", "--name="+clusterName))
	if node == "" {
		t.Fatalf("could not determine kind node for cluster %q", clusterName)
	}

	ns := fmt.Sprintf("cainjekt-java-e2e-%d", time.Now().UnixNano())
	svc := "https-server"
	t.Cleanup(func() {
		_ = tryCmd(30*time.Second, "kubectl", "delete", "ns", ns, "--wait=true")
	})
	runCmd(t, 30*time.Second, "kubectl", "create", "ns", ns)
	waitForDefaultServiceAccount(t, ns)

	caPath, srvCertPath, srvKeyPath := writeServicePKI(t, ns, svc)
	runCmd(t, 30*time.Second, "docker", "exec", node, "mkdir", "-p", "/etc/cainjekt")
	runCmd(t, 30*time.Second, "docker", "cp", caPath, node+":/etc/cainjekt/ca-bundle.pem")

	runCmd(t, 30*time.Second, "kubectl", "create", "secret", "generic", "https-server-tls",
		"-n", ns,
		"--from-file=tls.crt="+srvCertPath,
		"--from-file=tls.key="+srvKeyPath,
	)

	_ = tryCmd(20*time.Second, "docker", "exec", node, "sh", "-lc", "pkill -f '/cainjekt --idx' || true")
	runCmd(t, 30*time.Second, "docker", "exec", "-d", node, "/cainjekt", "--idx", pluginIdx)
	t.Cleanup(func() {
		_ = tryCmd(20*time.Second, "docker", "exec", node, "sh", "-lc",
			fmt.Sprintf("pkill -f %q", "/cainjekt --idx "+pluginIdx))
	})
	time.Sleep(2 * time.Second)

	serverManifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: https-server
  namespace: %s
  labels:
    app: https-server
spec:
  restartPolicy: Never
  containers:
  - name: server
    image: python:3.12-alpine
    command:
    - python
    - -u
    - -c
    - |
      import http.server, ssl
      class H(http.server.BaseHTTPRequestHandler):
          def do_GET(self):
              if self.path == "/healthz":
                  self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
              else:
                  self.send_response(404); self.end_headers()
          def log_message(self, *args):
              pass
      srv = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), H)
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
      ctx.load_cert_chain("/certs/tls.crt", "/certs/tls.key")
      srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
      srv.serve_forever()
    ports:
    - containerPort: 8443
    volumeMounts:
    - name: tls
      mountPath: /certs
      readOnly: true
  volumes:
  - name: tls
    secret:
      secretName: https-server-tls
---
apiVersion: v1
kind: Service
metadata:
  name: %s
  namespace: %s
spec:
  selector:
    app: https-server
  ports:
  - protocol: TCP
    port: 8443
    targetPort: 8443
`, ns, svc, ns)
	runCmdInput(t, 30*time.Second, serverManifest, "kubectl", "apply", "-f", "-")
	waitForPodReady(t, 3*time.Minute, ns, "https-server", "180s")

	serviceURL := fmt.Sprintf("https://%s.%s.svc.cluster.local:8443/healthz", svc, ns)

	for _, tc := range javaClientImages {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			image := buildJavaClientImageAndLoadToKind(t, clusterName, tc.image)
			suffix := tc.name

			// --- injected pod: CA injection enabled → TLS should succeed ---
			injectedName := "java-injected-" + suffix
			injectedPod := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  annotations:
    cainjekt.tsuzu.dev/enabled: "true"
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: %s
    imagePullPolicy: IfNotPresent
    command: ["sh", "-c", "sleep 600"]
`, injectedName, ns, image)
			runCmdInput(t, 30*time.Second, injectedPod, "kubectl", "apply", "-f", "-")
			waitForPodReady(t, 3*time.Minute, ns, injectedName, "180s")
			runCmd(t, 2*time.Minute, "kubectl", "exec", "-n", ns, injectedName, "--",
				"java", "-cp", "/tmp", "HttpsCheck", serviceURL)

			// --- plain pod: CA injection disabled → TLS should fail ---
			plainName := "java-plain-" + suffix
			plainPod := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  annotations:
    cainjekt.tsuzu.dev/enabled: "false"
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: %s
    imagePullPolicy: IfNotPresent
    command: ["sh", "-c", "sleep 600"]
`, plainName, ns, image)
			runCmdInput(t, 30*time.Second, plainPod, "kubectl", "apply", "-f", "-")
			waitForPodReady(t, 3*time.Minute, ns, plainName, "180s")
			out, err := runCmdWithInput(2*time.Minute, "", "kubectl", "exec", "-n", ns, plainName, "--",
				"java", "-cp", "/tmp", "HttpsCheck", serviceURL)
			if err == nil {
				t.Fatalf("expected TLS failure without CA injection, but command succeeded\noutput: %s", out)
			}
		})
	}
}

// buildJavaClientImageAndLoadToKind builds a Docker image from the given Java
// base image, compiles HttpsCheck.java inside it, and loads the resulting
// image into the kind cluster.
func buildJavaClientImageAndLoadToKind(t *testing.T, clusterName, baseImage string) string {
	t.Helper()

	tag := fmt.Sprintf("cainjekt/java-client:%d", time.Now().UnixNano())
	tmp := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmp, "HttpsCheck.java"), []byte(javaHttpsCheckSource), 0o644); err != nil {
		t.Fatalf("write HttpsCheck.java: %v", err)
	}

	dockerfile := fmt.Sprintf(`FROM %s
COPY HttpsCheck.java /tmp/
RUN javac -d /tmp /tmp/HttpsCheck.java
CMD ["sh", "-c", "sleep 600"]
`, baseImage)
	if err := os.WriteFile(filepath.Join(tmp, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	runCmd(t, 5*time.Minute, "docker", "build", "-t", tag, "-f", filepath.Join(tmp, "Dockerfile"), tmp)
	t.Cleanup(func() {
		_ = tryCmd(30*time.Second, "docker", "rmi", tag)
	})

	if out, err := runCmdWithInput(2*time.Minute, "", "kind", "load", "docker-image", "--name", clusterName, tag); err != nil {
		t.Logf("kind load docker-image failed, falling back to ctr import: %v\n%s", err, out)
		importImageViaCtr(t, clusterName, tag)
	}
	return tag
}
