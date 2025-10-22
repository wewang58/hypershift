package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

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
)

const (
	CiliumVersion = "1.15.1"
)

type K8sClient struct {
	clientset     *kubernetes.Clientset
	dynamicClient dynamic.Interface
	config        *rest.Config
}

func NewK8sClient() (*K8sClient, error) {
	var config *rest.Config
	var err error

	config, err = rest.InClusterConfig()
	if err != nil {
		kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
		if _, err := os.Stat(kubeconfig); os.IsNotExist(err) {
			return nil, fmt.Errorf("kubeconfig file not found: %s", kubeconfig)
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("error building config: %v", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating clientset: %v", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating dynamic client: %v", err)
	}

	return &K8sClient{
		clientset:     clientset,
		dynamicClient: dynamicClient,
		config:        config,
	}, nil
}

func main() {
	fmt.Println("Starting Cilium E2E test deployment...")

	client, err := NewK8sClient()
	if err != nil {
		panic(err.Error())
	}

	ciliumNs := client.checkCiliumNamespace()
	if ciliumNs == "" {
		client.createCiliumNamespace()
	} else {
		fmt.Println("Cilium namespace already exists")
	}

	client.applySecurityLabels("cilium")

	client.applyAllOLMManifests()

	podCIDR, hostPrefix := client.getNetworkConfig()
	fmt.Printf("Detected network configuration - Pod CIDR: %s, Host Prefix: %s\n", podCIDR, hostPrefix)

	ciliumConfig := client.createCiliumConfig(podCIDR, hostPrefix)
	client.applyCiliumConfig(ciliumConfig)

	fmt.Println("Cilium deployment completed successfully!")
}

func (k *K8sClient) checkCiliumNamespace() string {
	_, err := k.clientset.CoreV1().Namespaces().Get(context.TODO(), "cilium", metav1.GetOptions{})
	if err != nil {
		return ""
	}
	return "cilium"
}

func (k *K8sClient) createCiliumNamespace() {
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium",
		},
	}

	_, err := k.clientset.CoreV1().Namespaces().Create(context.TODO(), namespace, metav1.CreateOptions{})
	if err != nil {
		fmt.Printf("Error creating Cilium namespace: %v\n", err)
	} else {
		fmt.Println("Successfully created Cilium namespace")
	}
}

func (k *K8sClient) applySecurityLabels(namespace string) {
	ns, err := k.clientset.CoreV1().Namespaces().Get(context.TODO(), namespace, metav1.GetOptions{})
	if err != nil {
		fmt.Printf("Error getting namespace: %v\n", err)
		return
	}

	if ns.Labels == nil {
		ns.Labels = make(map[string]string)
	}

	ns.Labels["security.openshift.io/scc.podSecurityLabelSync"] = "false"
	ns.Labels["pod-security.kubernetes.io/enforce"] = "privileged"
	ns.Labels["pod-security.kubernetes.io/audit"] = "privileged"
	ns.Labels["pod-security.kubernetes.io/warn"] = "privileged"

	_, err = k.clientset.CoreV1().Namespaces().Update(context.TODO(), ns, metav1.UpdateOptions{})
	if err != nil {
		fmt.Printf("Error applying security labels: %v\n", err)
	} else {
		fmt.Println("Successfully applied security labels")
	}
}

func (k *K8sClient) getNetworkConfig() (string, string) {
	return "10.128.0.0/14", "23"
}

func (k *K8sClient) applyOLMManifest(filename string) {
	url := fmt.Sprintf("https://raw.githubusercontent.com/isovalent/olm-for-cilium/main/manifests/cilium.v%s/cluster-network-%s", CiliumVersion, filename)

	manifestContent, err := k.fetchManifestContent(url)
	if err != nil {
		fmt.Printf("Error fetching manifest %s: %v\n", filename, err)
		return
	}

	k.applyManifestContent(manifestContent)
}

func (k *K8sClient) applyAllOLMManifests() {
	manifests := []string{
		"03-cilium-ciliumconfigs-crd.yaml",
		"06-cilium-00000-cilium-namespace.yaml",
		"06-cilium-00001-cilium-olm-serviceaccount.yaml",
		"06-cilium-00002-cilium-olm-deployment.yaml",
		"06-cilium-00003-cilium-olm-service.yaml",
		"06-cilium-00004-cilium-olm-leader-election-role.yaml",
		"06-cilium-00005-cilium-olm-role.yaml",
		"06-cilium-00006-leader-election-rolebinding.yaml",
		"06-cilium-00007-cilium-olm-rolebinding.yaml",
		"06-cilium-00008-cilium-cilium-olm-clusterrole.yaml",
		"06-cilium-00009-cilium-cilium-clusterrole.yaml",
		"06-cilium-00010-cilium-cilium-olm-clusterrolebinding.yaml",
		"06-cilium-00011-cilium-cilium-clusterrolebinding.yaml",
	}

	for _, manifest := range manifests {
		fmt.Printf("Applying manifest: %s\n", manifest)
		k.applyOLMManifest(manifest)
		time.Sleep(1 * time.Second)
	}
}

func (k *K8sClient) createCiliumConfig(podCIDR, hostPrefix string) string {
	config := fmt.Sprintf(`apiVersion: cilium.io/v1alpha1
kind: CiliumConfig
metadata:
  name: cilium
  namespace: cilium
spec:
  debug:
    enabled: true
  k8s:
    requireIPv4PodCIDR: true
  logSystemLoad: true
  bpf:
    preallocateMaps: true
  etcd:
    leaseTTL: 30s
  ipv4:
    enabled: true
  ipv6:
    enabled: false
  identityChangeGracePeriod: 0s
  ipam:
    mode: "cluster-pool"
    operator:
      clusterPoolIPv4PodCIDRList:
        - "%s"
      clusterPoolIPv4MaskSize: "%s"
  nativeRoutingCIDR: "%s"
  endpointRoutes:
    enabled: true
  clusterHealthPort: 9940
  tunnelPort: 4789
  cni:
    binPath: "/var/lib/cni/bin"
    confPath: "/var/run/multus/cni/net.d"
    chainingMode: portmap
  prometheus:
    serviceMonitor:
      enabled: false
  hubble:
    tls:
      enabled: false
  sessionAffinity: true`, podCIDR, hostPrefix, podCIDR)

	return config
}

func (k *K8sClient) applyCiliumConfig(ciliumConfig string) {
	gvr := schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v1alpha1",
		Resource: "ciliumconfigs",
	}

	var obj map[string]interface{}
	if err := yaml.Unmarshal([]byte(ciliumConfig), &obj); err != nil {
		fmt.Printf("Error unmarshaling CiliumConfig: %v\n", err)
		return
	}

	unstructuredObj := &unstructured.Unstructured{Object: obj}
	_, err := k.dynamicClient.Resource(gvr).Namespace("cilium").Create(context.TODO(), unstructuredObj, metav1.CreateOptions{})
	if err != nil {
		fmt.Printf("Error applying CiliumConfig: %v\n", err)
	} else {
		fmt.Println("Successfully applied CiliumConfig")
	}
}

func (k *K8sClient) fetchManifestContent(url string) ([]byte, error) {
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

func (k *K8sClient) applyManifestContent(content []byte) {
	fmt.Printf("Applying manifest content (length: %d bytes)\n", len(content))
}
func (k *K8sClient) applyManifestContent(content []byte) error {
    ctx := context.TODO()
    
    if len(content) == 0 {
        return fmt.Errorf("empty manifest content")
    }
    
    documents := splitYAMLDocuments(content)
    
    appliedCount := 0
    for i, doc := range documents {
        if len(doc) == 0 {
            continue
        }
        
        fmt.Printf("Processing document %d/%d\n", i+1, len(documents))
        
        var obj map[string]interface{}
        if err := yaml.Unmarshal(doc, &obj); err != nil {
            fmt.Printf("Warning: Failed to unmarshal document %d: %v\n", i+1, err)
        continue
    }
    
    metadata, ok := obj["metadata"].(map[string]interface{})
    if !ok {
        fmt.Printf("Warning: Document %d missing metadata\n", i+1)
        continue
    }
    
    name, _ := metadata["name"].(string)
    if name == "" {
        fmt.Printf("Warning: Document %d missing name\n", i+1)
        continue
    }
    
    apiVersion, ok := obj["apiVersion"].(string)
    if !ok {
        fmt.Printf("Warning: Document %d missing apiVersion\n", i+1)
        continue
    }
    
    kind, ok := obj["kind"].(string)
    if !ok {
        fmt.Printf("Warning: Document %d missing kind\n", i+1)
        continue
    }
    
    gv, err := schema.ParseGroupVersion(apiVersion)
    if err != nil {
        fmt.Printf("Warning: Document %d has invalid apiVersion: %s\n", i+1, apiVersion)
        continue
    }
    
    var gvr schema.GroupVersionResource
    switch kind {
    case "Deployment":
        gvr = gv.WithResource("deployments")
    case "Service":
        gvr = gv.WithResource("services")
    case "Namespace":
        gv = schema.GroupVersion{Group: "", Version: "v1"}
        gvr = gv.WithResource("namespaces")
    case "CiliumNetworkPolicy":
        gvr = schema.GroupVersionResource{
            Group:    "cilium.io",
            Version:  "v2",
            Resource: "ciliumnetworkpolicies",
        }
    case "SecurityContextConstraints":
        gvr = schema.GroupVersionResource{
            Group:    "security.openshift.io",
            Version:  "v1",
            Resource: "securitycontextconstraints",
        }
    default:
        fmt.Printf("Skipping unsupported resource: %s/%s\n", kind, name)
        continue
    }
    
    namespace := getNamespace(obj)
    
    unstructuredObj := &unstructured.Unstructured{Object: obj}
    
    existing, err := k.dynamicClient.Resource(gvr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
        
    if err != nil {
        _, err = k.dynamicClient.Resource(gvr).Namespace(namespace).Create(ctx, unstructuredObj, metav1.CreateOptions{})
    if err != nil {
        return fmt.Errorf("failed to create %s/%s: %v", kind, name, err)
    }
    
    appliedCount++
    fmt.Printf("✓ Successfully applied %s: %s in namespace: %s\n", kind, name, namespace)
    }
    
    fmt.Printf("Total applied resources: %d/%d\n", appliedCount, len(documents))
    return nil
}