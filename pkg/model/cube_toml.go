package model

type CubeToml struct {
	InternalEnv struct {
		CollectorServerUrl string `toml:"collector-server-url,omitempty"`
		MonitorApiUrl      string `toml:"monitor-api-url,omitempty"`
	} `toml:"internal-env,omitempty"`

	Cube struct {
		Version            string `toml:"version,omitempty"`
		Provider           bool   `toml:"provider"`
		ClusterName        string `toml:"cluster-name,omitempty"`
		ClusterDescription string `toml:"cluster-description,omitempty"`
		ClusterType        string `toml:"cluster-type,omitempty"`
		ClusterID          string `toml:"cluster-id,omitempty"`
		ClosedNetwork      bool   `toml:"closed-network,omitempty"`
		AlertLanguage      string `toml:"alert-language,omitempty"`
		StorageClassName   string `toml:"storage-class-name,omitempty"`
		LocalRepository    string `toml:"local-repository,omitempty"`
		DebugMode          bool   `toml:"debug-mode,omitempty"`
		InstallDir         string `toml:"install-dir,omitempty"`
		CertValidityDays   int    `toml:"cert-validity-days,omitempty"`
	} `toml:"cube,omitempty"`

	Kubernetes struct {
		Version          string   `toml:"version,omitempty"`
		ServiceCidr      string   `toml:"service-cidr,omitempty"`
		PodCidr          string   `toml:"pod-cidr,omitempty"`
		ApiSans          []string `toml:"api-sans,omitempty"`
		AuditLogEnable   bool     `toml:"audit-log-enable"`
		KubeProxyMode    string   `toml:"kube-proxy-mode"`
		ContainerRuntime string   `toml:"container-runtime"`
		VxlanMode        bool     `toml:"vxlan-mode"`

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
			Name       string   `toml:"name,omitempty"`
			IP         []string `toml:"ip,omitempty"`
			PrivateIP  []string `toml:"private-ip,omitempty"`
			InternalLb string   `toml:"internal-lb,omitempty"`
			//ExternalLb     string   `toml:"external-lb,omitempty"`
			IngressHost    string `toml:"ingress-host,omitempty"`
			NodePortURL    string `toml:"node-port-url,omitempty"`
			NodePortrange  string `toml:"node-portrange,omitempty"`
			Isolated       bool   `toml:"isolated"`
			HaproxyInstall bool   `toml:"haproxy-install"`

			NodeOptions []string `toml:"node-options,omitempty"`
		} `toml:"master,omitempty"`

		Nodes  []StrNode    `toml:"nodes,omitempty"`
		Labels []NodeLabels `toml:"labels,omitempty"`
	} `toml:"node-pool,omitempty"`

	//Addon struct {
	//	Install              bool   `toml:"install,omitempty"`
	//	ChartRepoUrl         string `toml:"chart-repo-url,omitempty"`
	//	ChartRepoProjectName string `toml:"chart-repo-project-name,omitempty"`
	//	AutoUpload           bool   `toml:"auto-update,omitempty"`
	//} `toml:"addon,omitempty"`

	/*
		LiteEdge struct {
			HomepageUrl  string `toml:"homepage-url,omitempty"`
			ImageVersion struct {
				Modbus        string `toml:"modbus,omitempty"`
				Opcua         string `toml:"opcua,omitempty"`
				Xgt           string `toml:"xgt,omitempty"`
				WebApi        string `toml:"web-api,omitempty"`
				WebClient     string `toml:"web-client,omitempty"`
				EventServer   string `toml:"event-server,omitempty"`
				DbSaver       string `toml:"db-saver,omitempty"`
				EventDetector string `toml:"event-detector,omitempty"`
				K8sApiGateway string `toml:"k8s-api-gateway,omitempty"`
			} `toml:"image-version,omitempty"`

			Edge struct {
				IP        []string `toml:"ip,omitempty"`
				PrivateIP []string `toml:"private-ip,omitempty"`
			} `toml:"edge,omitempty"`

			Kakao struct {
				ApiKey       string `toml:"api-key,omitempty"`
				SenderKey    string `toml:"sender-key,omitempty"`
				TempCdsAlarm string `toml:"temp-cds-alarm,omitempty"`
			} `toml:"kakao,omitempty"`

			Mail struct {
				Host     string `toml:"host,omitempty"`
				Port     int    `toml:"port,omitempty"`
				UserName string `toml:"username,omitempty"`
				Password string `toml:"password,omitempty"`
			} `toml:"mail,omitempty"`
		} `toml:"liteedge,omitempty"`
	*/
	SharedStorage struct {
		Install           bool   `toml:"install"`
		StorageIP         string `toml:"storage-ip,omitempty"`
		PrivateIP         string `toml:"private-ip,omitempty"`
		VolumeDir         string `toml:"volume-dir,omitempty"`
		VolumeSize        int    `toml:"volume-size,omitempty"`
		StorageType       string `toml:"storage-type,omitempty"`
		EfsFileSystemId   string `toml:"efs-file-system-id,omitempty"`
		StorageAccount    string `toml:"storage-account,omitempty"`
		VolumeBindingMode string `toml:"volume-binding-mode,omitempty"`
	} `toml:"shared-storage,omitempty"`

	PrivateRegistry struct {
		Install        bool   `toml:"install"`
		BackupFilePath string `toml:"backup-file-path,omitempty"`
		RegistryIP     string `toml:"registry-ip,omitempty"`
		RegistryDomain string `toml:"registry-domain,omitempty"`
		PrivateIP      string `toml:"private-ip,omitempty"`
		DataDir        string `toml:"data-dir,omitempty"`
		PublicCert     bool   `toml:"public-cert"`
		CertFile       struct {
			SslCertificate    string `toml:"ssl-certificate,omitempty"`
			SslCertificateKey string `toml:"ssl-certificate-key,omitempty"`
		} `toml:"cert-file,omitempty"`
	} `toml:"private-registry,omitempty"`

	//Eks struct {
	//	KubeVersion     string `toml:"kube-version"`
	//	ConfigPath      string `toml:"config-path"`
	//	CredentialsPath string `toml:"credentials-path"`
	//	BillingGroupId  string `toml:"billing-group-id"`
	//} `toml:"eks,omitempty"`
	//
	//Gke struct {
	//	KeyFilePath string `toml:"key-file-path"`
	//} `toml:"gke,omitempty"`
	//
	//Azure struct {
	//	VirtualNetworkName        string `toml:"virtual-network-name,omitempty"`
	//	SubnetName                string `toml:"subnet-name,omitempty"`
	//	SecurityGroupName         string `toml:"security-group-name,omitempty"`
	//	PrimaryAvailablitySetName string `toml:"primary-availablity-set-name,omitempty"`
	//	ResourceGroup             string `toml:"resource-group,omitempty"`
	//	RouteTableName            string `toml:"route-table-name,omitempty"`
	//	SubscriptionID            string `toml:"subscription-id"`
	//	ClientID                  string `toml:"client-id"`
	//	ClientSecret              string `toml:"client-secret"`
	//	TenantID                  string `toml:"tenant-id"`
	//} `toml:"azure,omitempty"`
}

type StrNode struct {
	IP          []string `toml:"ip,omitempty"`
	PrivateIP   []string `toml:"private-ip,omitempty"`
	NodeOptions []string `toml:"node-options,omitempty"`
}

type NodeLabels struct {
	IP     []string `toml:"ip,omitempty"`
	Labels []string `toml:"labels,omitempty"`
	Taints []string `toml:"taints,omitempty"`
}
