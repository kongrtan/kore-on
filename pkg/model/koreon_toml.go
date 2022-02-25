package model

type KoreonToml struct {
	Koreon struct {
		Version            string `toml:"version,omitempty"`
		Provider           bool   `toml:"provider"`
		ClusterName        string `toml:"cluster-name,omitempty"`
		ClusterDescription string `toml:"cluster-description,omitempty"`
		ClusterType        string `toml:"cluster-type,omitempty"`
		ClusterID          string `toml:"cluster-id,omitempty"`
		AlertLanguage      string `toml:"alert-language,omitempty"`
		StorageClassName   string `toml:"storage-class-name,omitempty"`
		DebugMode          bool   `toml:"debug-mode,omitempty"`
		InstallDir         string `toml:"install-dir,omitempty"`
		CertValidityDays   int    `toml:"cert-validity-days,omitempty"`
		//#Airgap
		//ArchiveRepo                bool   `toml:"archive-repo"`
		ClosedNetwork              bool   `toml:"closed-network,omitempty"`
		LocalRepository            string `toml:"local-repository,omitempty"`
		LocalRepositoryArchiveFile string `toml:"local-repository-archive-file"`
	} `toml:"koreon,omitempty"`

	Kubernetes struct {
		Version          string   `toml:"version,omitempty"`
		ServiceCidr      string   `toml:"service-cidr,omitempty"`
		PodCidr          string   `toml:"pod-cidr,omitempty"`
		ApiSans          []string `toml:"api-sans,omitempty"`
		AuditLogEnable   bool     `toml:"audit-log-enable"`
		KubeProxyMode    string   `toml:"kube-proxy-mode"`
		ContainerRuntime string   `toml:"container-runtime"`
		VxlanMode        bool     `toml:"vxlan-mode"`
		NodePortRange    string   `toml:"node-port-range,omitempty"`

		Etcd struct {
			IP            []string `toml:"ip,omitempty"`
			PrivateIP     []string `toml:"private-ip,omitempty"`
			EncryptSecret bool     `toml:"encrypt-secret,omitempty"`
		} `toml:"etcd,omitempty"`
	} `toml:"kubernetes,omitempty"`

	NodePool struct {
		DataDir string `toml:"data-dir,omitempty"`

		Provider struct {
			Name     string `toml:"name,omitempty"`
			Location string `toml:"location,omitempty"`
		} `toml:"provider,omitempty"`

		Security struct {
			SSHUserID      string `toml:"ssh-user-id,omitempty"`
			SSHPort        int    `toml:"ssh-port,omitempty"`
			PrivateKeyPath string `toml:"private-key-path,omitempty"`
			KubeConfigPath string `toml:"kube-config-path"`
		} `toml:"security,omitempty"`

		Master struct {
			Name      string   `toml:"name,omitempty"`
			IP        []string `toml:"ip,omitempty"`
			PrivateIP []string `toml:"private-ip,omitempty"`
			LbIP      string   `toml:"lb-ip,omitempty"`

			IngressHost string `toml:"ingress-host,omitempty"`
			NodePortURL string `toml:"node-port-url,omitempty"`

			Isolated       bool `toml:"isolated"`
			HaproxyInstall bool `toml:"haproxy-install"`
		} `toml:"master,omitempty"`

		Node StrNode `toml:"node,omitempty"`
	} `toml:"node-pool,omitempty"`

	SharedStorage struct {
		Install    bool   `toml:"install"`
		StorageIP  string `toml:"storage-ip,omitempty"`
		PrivateIP  string `toml:"private-ip,omitempty"`
		VolumeDir  string `toml:"volume-dir,omitempty"`
		VolumeSize int    `toml:"volume-size,omitempty"`
		//StorageType       string `toml:"storage-type,omitempty"`

	} `toml:"shared-storage,omitempty"`

	PrivateRegistry struct {
		Install             bool   `toml:"install"`
		RegistryIP          string `toml:"registry-ip,omitempty"`
		RegistryDomain      string `toml:"registry-domain,omitempty"`
		PrivateIP           string `toml:"private-ip,omitempty"`
		DataDir             string `toml:"data-dir,omitempty"`
		PublicCert          bool   `toml:"public-cert"`
		RegistryArchiveFile string `toml:"registry-archive-file"`
		CertFile            struct {
			SslCertificate    string `toml:"ssl-certificate,omitempty"`
			SslCertificateKey string `toml:"ssl-certificate-key,omitempty"`
		} `toml:"cert-file,omitempty"`
	} `toml:"private-registry,omitempty"`
}

type StrNode struct {
	IP          []string `toml:"ip,omitempty"`
	PrivateIP   []string `toml:"private-ip,omitempty"`
	NodeOptions []string `toml:"node-options,omitempty"`
}

// constructor function
func (a *KoreonToml) Fill_defaults() {
	a.Koreon.Version = "aaa"
}
