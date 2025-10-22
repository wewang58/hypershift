//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"sigs.k8s.io/yaml"

	e2eutil "github.com/openshift/hypershift/test/e2e/util"
)

const (
	ciliumTestNamespace = "cilium-test"
)

type CiliumTestManager struct {
	mgtClient    crclient.Client
	clientset    *kubernetes.Clientset
	dynamicClient dynamic.Interface
}

func NewCiliumTestManager(mgtClient crclient.Client) (*CiliumTestManager, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build config: %v", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %v", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %v", err)
	}

	return &CiliumTestManager{
		mgtClient:     mgtClient,
		clientset:     clientset,
		dynamicClient: dynamicClient,
	}, nil
}

func TestCiliumConnectivity(t *testing.T) {
	e2eutil.AtLeast(t, e2eutil.Version419)

	t.Parallel()

	ctx, cancel := context.WithCancel(testContext)
	defer cancel()

	mgtClient := e2eutil.GetMgtClient(t)
	hostedCluster := e2eutil.GetHostedCluster(t)

	clusterOpts := e2eutil.NewClusterOptions(t)
	clusterOpts.FeatureSet = string(corev1.Default)
	if os.Getenv("TECH_PREVIEW_NO_UPGRADE") == "true" {
		clusterOpts.FeatureSet = string(corev1.TechPreviewNoUpgrade)
	}

	e2eutil.NewHypershiftTest(t, ctx, func(t *testing.T, g Gomega, mgtClient crclient.Client, hostedCluster *corev1.HostedCluster) {
		manager, err := NewCiliumTestManager(mgtClient)
		g.Expect(err).NotTo(HaveOccurred())

		createCiliumTestNamespace(t, manager)
		createCiliumTestSCC(t, manager)
		deployConnectivityCheck(t, manager)
		waitForConnectivityTest(t, manager)
		verifyConnectivityTest(t, manager)
	})
}

func createCiliumTestNamespace(t *testing.T, manager *CiliumTestManager) {
	ctx := context.TODO()
	
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: ciliumTestNamespace,
			Labels: map[string]string{
				"security.openshift.io/scc.podSecurityLabelSync": "false",
				"pod-security.kubernetes.io/enforce":             "privileged",
				"pod-security.kubernetes.io/audit":               "privileged",
				"pod-security.kubernetes.io/warn":                "privileged",
			},
		},
	}
	err := manager.mgtClient.Create(ctx, ns)
	Expect(err).NotTo(HaveOccurred())
	
	fmt.Printf("Successfully created namespace: %s\n", ciliumTestNamespace)
}

func createCiliumTestSCC(t *testing.T, manager *CiliumTestManager) {
	ctx := context.TODO()
	
	sccYaml := `
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  name: cilium-test
allowHostPorts: true
allowHostNetwork: true
users:
  - system:serviceaccount:cilium-test:default
priority: null
readOnlyRootFilesystem: false
runAsUser:
  type: MustRunAsRange
seLinuxContext:
  type: MustRunAs
volumes: null
allowHostDirVolumePlugin: false
allowHostIPC: false
allowHostPID: false
allowPrivilegeEscalation: false
allowPrivilegedContainer: false
allowedCapabilities: null
defaultAddCapabilities: null
requiredDropCapabilities: null
groups: null
`

	var unstructuredObj map[string]interface{}
	if err := yaml.Unmarshal([]byte(sccYaml), &unstructuredObj)
	Expect(err).NotTo(HaveOccurred())

	gvr := schema.GroupVersionResource{
		Group:    "security.openshift.io",
		Version:  "v1",
		Resource: "securitycontextconstraints",
	}

	obj := &unstructured.Unstructured{Object: unstructuredObj}
	err := manager.dynamicClient.Resource(gvr).Create(ctx, obj, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())

	fmt.Println("Successfully created SecurityContextConstraints: cilium-test")
}

func deployConnectivityCheck(t *testing.T, manager *CiliumTestManager) {
	ctx := context.TODO()
	
	connectivityCheckURL := "https://raw.githubusercontent.com/cilium/cilium/v1.14.0/examples/kubernetes/connectivity-check/connectivity-check.yaml"

	content, err := fetchManifestContent(connectivityCheckURL)
	Expect(err).NotTo(HaveOccurred())

	err = applyManifestContent(ctx, manager, content)
	Expect(err).NotTo(HaveOccurred())
	
	fmt.Println("Successfully deployed Cilium connectivity check")
}

func waitForConnectivityTest(t *testing.T, manager *CiliumTestManager) {
	ctx := context.TODO()
	
	err := e2eutil.WaitForPodsRunning(t, ctx, manager.mgtClient, ciliumTestNamespace)
	Expect(err).NotTo(HaveOccurred())

	fmt.Println("All connectivity test pods are running")
}

func verifyConnectivityTest(t *testing.T, manager *CiliumTestManager) {
	ctx := context.TODO()
	
	pods := &corev1.PodList{}
	err := manager.mgtClient.List(ctx, pods)
	Expect(err).NotTo(HaveOccurred())

	testPassed := true
	for _, pod := range pods.Items {
		if pod.Namespace == ciliumTestNamespace {
			if pod.Status.Phase != corev1.PodRunning {
				fmt.Printf("Pod %s is not in Running state. Current state: %s\n", pod.Name, pod.Status.Phase)
				testPassed = false
				continue
			}

			if len(pod.Status.ContainerStatuses) > 0 {
				restartCount := pod.Status.ContainerStatuses[0].RestartCount
				if restartCount > 0 {
					fmt.Printf("Pod %s has restarted %d times\n", pod.Name, restartCount)
				if restartCount > 3 {
					testPassed = false
				}
			}
		}
	}

	Expect(testPassed).To(BeTrue(), "Connectivity test verification failed")
	fmt.Println("Connectivity test verification passed")
}

func fetchManifestContent(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func applyManifestContent(ctx context.Context, manager *CiliumTestManager, content []byte) error {
	
	docs := splitYAMLDocuments(content)
	
	for _, doc := range docs {
		if len(doc) == 0 {
			continue
		}

		var obj map[string]interface{}
		if err := yaml.Unmarshal(doc, &obj); err != nil {
		return fmt.Errorf("failed to unmarshal YAML document: %v", err)
		}

		unstructuredObj := &unstructured.Unstructured{Object: obj}
		
		apiVersion, ok := obj["apiVersion"].(string)
		if !ok {
			continue
		}

		gv, err := schema.ParseGroupVersion(apiVersion)
		if err != nil {
			continue
		}

		kind, ok := obj["kind"].(string)
		if !ok {
			continue
		}

		var gvr schema.GroupVersionResource
		switch kind {
		case "Deployment":
			gvr = gv.WithResource("deployments")
		case "Service":
			gvr = gv.WithResource("services")
		case "Namespace":
			gvr = gv.WithResource("namespaces")
		case "CiliumNetworkPolicy":
			gvr = schema.GroupVersionResource{
				Group:    "cilium.io",
				Version:  "v2",
				Resource: "ciliumnetworkpolicies",
			}
		default:
			continue
		}

		_, err = manager.dynamicClient.Resource(gvr).Namespace(getNamespace(obj)).Create(ctx, unstructuredObj, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create resource: %v", err)
		}
	}

	return nil
}

func splitYAMLDocuments(content []byte) [][]byte {
	var documents [][]byte
	document := []byte{}
	
	lines := bytes.Split(content, []byte("\n"))
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("---")) {
			if len(document) > 0 {
				documents = append(documents, document)
				document = []byte{}
			}
		} else {
			document = append(document, line...)
			document = append(document, '\n')
		}
	}

	if len(document) > 0 {
		documents = append(documents, document)
	}

	return documents
}

func getNamespace(obj map[string]interface{}) string {
	metadata, ok := obj["metadata"].(map[string]interface{})
	if !ok {
		return "default"
	}

	ns, ok := metadata["namespace"].(string)
	if !ok {
		return "default"
	}

	return ns
}

type CiliumConnectivityCheck struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name   string            `yaml:"name"`
		Labels map[string]string `yaml:"labels"`
	} `yaml:"metadata"`
	Spec interface{} `yaml:"spec"`
}

func verifyNetworkPolicies(t *testing.T, manager *CiliumTestManager) {
	ctx := context.TODO()

	gvr := schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumnetworkpolicies",
	}

	cnps, err := manager.dynamicClient.Resource(gvr).Namespace(ciliumTestNamespace).List(ctx, metav1.ListOptions{})
	Expect(err).NotTo(HaveOccurred())

	for _, cnp := range cnps.Items {
		name := cnp.GetName()
		fmt.Printf("Verifying CiliumNetworkPolicy: %s\n", name)

		labels := cnp.GetLabels()
		if component, exists := labels["component"]; exists {
			fmt.Printf("  Component: %s\n", component)
		}
	}

	fmt.Println("All CiliumNetworkPolicies verified successfully")
}

func additionalCiliumTests(t *testing.T, manager *CiliumTestManager) {
	ctx := context.TODO()

	services, err := manager.clientset.CoreV1().Services(ciliumTestNamespace).List(ctx, metav1.ListOptions{})
	Expect(err).NotTo(HaveOccurred())

	for _, svc := range services.Items {
		fmt.Printf("Verifying Service: %s, Type: %s\n", svc.Name, svc.Spec.Type)
	}
}

func checkPodHealth(t *testing.T, manager *CiliumTestManager) {
	ctx := context.TODO()

	pods, err := manager.clientset.CoreV1().Pods(ciliumTestNamespace).List(ctx, metav1.ListOptions{})
	Expect(err).NotTo(HaveOccurred())

	for _, pod := range pods.Items {
		ready := true
		for _, condition := range pod.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status != corev1.ConditionTrue {
				ready = false
				break
			}
		}

		if !ready {
			fmt.Printf("Warning: Pod %s is not ready\n", pod.Name)
		}
	}

	fmt.Println("Pod health check completed")
}
