package conf

var GWorkDir string
var BaseDir string
var IsCliMode = true
var ImageName = "regi.acornsoft.io/cocktail-common/cubetool:1.0.2.B000004"

var Version = "unknown_version"
var CommitId = "unknown_commitid"
var BuildDate = "unknown_builddate"

const (
	CubeVersion    = "2.7.0"
	CubeSvcVersion = "v1.13.5-R6"

	CubeKey = "/lib/apk/db/20160708.key"
	//CubeKey = "/Users/cloud/.ansible/cube.key"
	//#registry_passwd: "C0ckt@1lAdmin"
)

const (
	CubeBaseDir    = "/cube"
	CubeDestDir    = "generated"
	CubeConfigFile = "cube.toml"
	Kubeconfig     = "acloud-client-kubeconfig"

	AnsibleConfigPath = "/cubescripts/group_vars/all.yml"
	AnsibleConfig     = "/cubescripts/ansible.cfg"
	AddNodeYaml       = "/cubescripts/add-node.yml"
	UpgradeYaml       = "/cubescripts/upgrade.yml"
	DelNodeYaml       = "/cubescripts/remove-node.yml"
	CreateYaml        = "/cubescripts/cluster.yml"
	ResetYaml         = "/cubescripts/reset.yml"
	PreDestroyYaml    = "/cubescripts/pre-destroy.yml"

	MasterCredentailPath      = "/cubescripts/group_vars/masters.yaml"
	NodeCredentailPath        = "/cubescripts/group_vars/node.yaml"
	AnsibelConfigPathInDocker = "/cube/cubescripts/group_vars/all.yml"
	InventoryPath             = "/cubescripts/inventories/inventory"

	//PrintPrefix = "◐"
	PrintAnsiblePrefix = "⊙"

	SecretPrivateKey = "svr_id_rsa"
	SecretPublicKey  = "svr_id_rsa.pub"
)

//cluster scale
const (
	ClusterLagre  = "large"  //(HA) : 워커 노드 250대 이상, External ETCD 클러스터 구성, Shared Storage 이중화 옵션
	ClusterMedium = "medium" //(HA) : 워커 노드 10 ~ 250대 규모, Stacked ETCD 구성,  Shared Storage 이중화 옵션
	ClusterSmall  = "small"  // : 워커노드 10대 미만 규모, 단일 마스터(백업 구성), Shared Storage 이중화 구성(옵션)
	ClusterTiny   = "tiny"   // : Poc 또는 테스트 목적의 클러스터
	ClusterKaaS   = "kaas"   // : 퍼블릭 프로바이더의 K8s as a Service 사용. 애드온과 인그레스 구성
)

// k8s v1.13.x etcd peer cert path
const (
	EtcdCaPath       = "/etc/kubernetes/pki/etcd/ca.crt"
	EtcdPeerKeyPath  = "/etc/kubernetes/pki/etcd/peer.key"
	EtcdPeerCertPath = "/etc/kubernetes/pki/etcd/peer.crt"
)

const (
	SUCCESS_FORMAT = "\033[1;32m%s\033[0m\n"
	STATUS_FORMAT  = "\033[1;32m%s\033[0m"
	ERROR_FORMAT   = "\x1B[1;3;31m%s\x1B[0m\n"
	CHECK_FORMAT   = "\033[1;34m%s\033[0m"
)

// To deploy monitoring addon and cocktail in case of minikube (dedicated)
var CocktailYml = []string{
	"namespace.yaml",

	"alertmanager-cm.yaml",
	"alertmanager-deploy.yaml",
	"alertmanager-networkpolicy.yaml",
	"alertmanager-pvc.yaml",
	"alertmanager-rbac.yaml",
	"alertmanager-svc.yaml",
	"alertmanager-svc-nodeport.yaml",
	"alertmanager-template.yaml",

	"kube-state-metrics-deploy.yaml",
	"kube-state-metrics-networkpolicy.yaml",
	"kube-state-metrics-rbac.yaml",
	"kube-state-metrics-svc.yaml",

	"node-exporter-ds.yaml",
	"node-exporter-rbac.yaml",
	"node-exporter-svc.yaml",
	"prometheus-cm.yaml",
	"prometheus-deploy.yaml",
	"prometheus-networkpolicy.yaml",
	"prometheus-pvc.yaml",
	"prometheus-rbac.yaml",
	"prometheus-rules.yaml",
	"prometheus-svc.yaml",
	"prometheus-svc-nodeport.yaml",

	"cocktail-smdb-init.yaml",
	"cocktail-monitoring.yaml",
	"cocktail-client.yaml",
	"cocktail-client-apollomq.yaml",
	"cocktail-dashboard.yaml",
	"cocktail-sm-api.yaml",
	"cocktail-sm-db.yaml",
}

var DefaultConfig = map[string]string{
	"k8s_version":           "1.13.1",
	"cluster_name":          "cube",
	"master_ip":             "",
	"worker_ip":             "",
	"master_private_ip":     "",
	"worker_private_ip":     "",
	"domain_name":           "acornsoft.io",
	"kubernetes_service_ip": "100.64.0.1",
	"cloud_provider":        "",
	"master_node_count":     "1",
	"worker_node_count":     "2",
	"ingress":               "true",
	"monitoring":            "false",
	"grafana":               "false",
	"cocktail":              "false",
	"kube_dash":             "false",
	"logging":               "false",
	"haproxy":               "false",
	"key_path":              "",
	"nfs_ip":                "",
	"nfs_mountdir":          "",
	"storage_size":          "",
	"data_root_dir":         "/data",
	"alertmsg_lang":         "ko",
	"lb_ip":                 "",
	"api_insecure_port":     "8080",
	"api_secure_port":       "6443",
	"etcd1":                 "2379",
	"etcd2":                 "2380",
	"elb_api_fqdn":          "", // virtualbox - master1, baremetal - lb_ip(cube.yaml) > master1
	"cluster_id":            "",
	"storage_account_type":  "",
	"release_name":          "cocktail",
	"registry":              "cube-hub.acornsoft.io",
}

const (
	CubeActionCreate  = 0
	CubeActionDestroy = 1
	CubeActionUpgrade = 2
	CubeActionNode    = 3
)

var DefaultSecret = map[string]string{
	"id":              "admin",
	"passwd":          "Pass0000@",
	"builder_capem":   "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlEQnpDQ0FlK2dBd0lCQWdJSkFJVExFS1lrd3phM01BMEdDU3FHU0liM0RRRUJDd1VBTUJveEdEQVdCZ05WDQpCQU1NRDJsd0xURTNNaTB6TVMweE55MDRPREFlRncweE56RXhNekF3TnpNNE5UTmFGdzB5TnpFeE1qZ3dOek00DQpOVE5hTUJveEdEQVdCZ05WQkFNTUQybHdMVEUzTWkwek1TMHhOeTA0T0RDQ0FTSXdEUVlKS29aSWh2Y05BUUVCDQpCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFKYStock8zMkYxZTFBWWxlM1pGSUFiR1RSZEx0WVdGUTl3YVlDVDM0aFNODQpTR0hlVkJPZHFGYW5pR2ZBSEFiZU5oVlZRWUZDd25tSUovWUVBdW10dmVENThmMzc5ZXFSdVBVUmx6a21XTkRlDQo4L2MvbzRWNTJvYmRSSFVVQWtOTldnSk12aHpuKzEwY1p5V0FhN1JFUlVzOFdrR0hjVnd5aTlrcXdkNGNLZDNkDQpuaXhCTkZhbzFwa3VzUnZaem5nUDJ1N2FFa1RKU0dRNEg2T3F0T1BWMHhRMVQ5MDh2cDR5MHdaTzJ2WlV5SXhkDQowK28rdmF4UWl5b3NFZTR3VTloK0NvL2Vhb09mbmxGeDEzQWlQSndMSWFjOU0vZUhlWm1NQUdTQWRkY3h5V0YvDQoyVEtUVGdaWHFDRm5RMU1oOExiTjhSTEZBK0JFNEdwbHUrUWc5OWlEdlJrQ0F3RUFBYU5RTUU0d0hRWURWUjBPDQpCQllFRksxeXJwR04xUStLVmwwbm82cFdqaVBxUzdRSU1COEdBMVVkSXdRWU1CYUFGSzF5cnBHTjFRK0tWbDBuDQpvNnBXamlQcVM3UUlNQXdHQTFVZEV3UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFFQTlRWWg0DQpjVjFjT01JeFdLVXpzL1JTcmR2MUQ3cWpuc1ErenpzR2VDQWszWlNHQTdVRTVVSkhUMU5Pd3Y4ZXloNmVqQllTDQpjaFlMQ3Y2WlN4TnUzQ2RYa2xUS2Z1WDdXcUhKQzBUVXR3clVwM0ZoditYcjJwY2J3UWxTeG85TFlmWUxOOWF0DQpscTl2ZzZ3eWswWFBVNFM3WC9kRmJtamJqZ00ybTdsZyt4M1JoODJVaWxueU5FZDV6dGFsOGNtM3ZEeXQzb2pFDQo0em8yd0EwdnRXcU5wM1o4OUN2SU9aTjd4ZG55Wm9wK3hRMXFmZFFUYXJxb0xGY2M2Q2duUUVnc2xSWVZzNCtLDQpzR2FJMjlSVGJpNVBMckQ3dGV2UE55RHNlV2lRVW80RUkvdWpPL254K2NhRlJha2ZMelVlNWwzVWtINTUyQjU2DQpZaFk1WGNJWkYwYm1Xbjg9DQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t",
	"builder_certpem": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlDeERDQ0FheWdBd0lCQWdJQkF6QU5CZ2txaGtpRzl3MEJBUVVGQURBYU1SZ3dGZ1lEVlFRRERBOXBjQzB4DQpOekl0TXpFdE1UY3RPRGd3SGhjTk1UY3hNVE13TURjek9EVXpXaGNOTWpjeE1USTRNRGN6T0RVeldqQVlNUll3DQpGQVlEVlFRRERBMWtiMk5yWlhJdVkyeHBaVzUwTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCDQpDZ0tDQVFFQXlIUnBjK0xJakR3OGwxaFlqejVvV3h1SStjU0t1QnNyU21JSXpGRWZxdDgyVGp1aEJUNDB6UWtVDQpPNGdmeXNtVVdDZ056TFZsV01Hdnc1QW9JUEJNVUFyRVYxKzdDc2VwUFZzQlZFbEJkRDZFanpaNHBwWUdGZlovDQpHVFRhTm1FQitsYi9tNFBJZXFpdFhUVkpjL1JFZGdOc0xzbk04QnExb21iUllCWEx2UnVKeU5RbGNlWmp2OFh0DQowNHgxNWswNlhOcXA3di9YaHdPd1pOTjlvaGJVamVYN29ZZWwvY0F2ZHFsVWlSNzBGY01iWlNxZmNHU1FJS1R0DQptQ3BQd3Ixck5EcUVsOWlNWnNEWWFsN2EzK0M5ZHNCNk1lZnh6MkIrUmRCRjJhU3NZdTE5dUtBcktEMTlTRkgvDQpuMnVmZEJ6SG4wSEprOGZZR1J6QWpsc2VDVVF3WndJREFRQUJveGN3RlRBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGDQpCUWNEQWpBTkJna3Foa2lHOXcwQkFRVUZBQU9DQVFFQWFST3pid3E5ZDBWTHVXWlJhbVVPYmhQYkw1cm5YMkw3DQowUVBxZkJyWkc1c0RXNWRYQmdyL0R6bVpxZWFLV3lndW9ncHBlZzRXZ2sycnlpTlpWZ1d3N3preGI4aFZYUVlMDQp2Qit6dmtoUlJtMGlNZ0Mzc3ZWUVlsMnFHWWJ6M005MEluRnYwclBJZHhNaEZFVG5mZjhvVDJlUDJnbGora3VJDQpnT3pBeTBzMHpzZ25TV3pnYnpMMm1xem04NkFOYXN6MXJBMkV2QXNXbGhnZENBUncySG8zUmxCR053ZkhIUWFPDQp3cEFTd0k1SlRqOE9OV0ZjcUZrYnBJTEdXQkFSOGtiRGNiT3dwSE1DK3N5SFVHbnVlb3hSbm54cFZHVm1yMDUvDQozSHZEN29aRkNkV1dVa3ljc1BsK2RObjJBSGpjQXpwNEJHNjEydFF2aU1sVVMxUzJPbmcwQ0E9PQ0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ==",
	"builder_keypem":  "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ0KTUlJRW93SUJBQUtDQVFFQXlIUnBjK0xJakR3OGwxaFlqejVvV3h1SStjU0t1QnNyU21JSXpGRWZxdDgyVGp1aA0KQlQ0MHpRa1VPNGdmeXNtVVdDZ056TFZsV01Hdnc1QW9JUEJNVUFyRVYxKzdDc2VwUFZzQlZFbEJkRDZFanpaNA0KcHBZR0ZmWi9HVFRhTm1FQitsYi9tNFBJZXFpdFhUVkpjL1JFZGdOc0xzbk04QnExb21iUllCWEx2UnVKeU5RbA0KY2VaanY4WHQwNHgxNWswNlhOcXA3di9YaHdPd1pOTjlvaGJVamVYN29ZZWwvY0F2ZHFsVWlSNzBGY01iWlNxZg0KY0dTUUlLVHRtQ3BQd3Ixck5EcUVsOWlNWnNEWWFsN2EzK0M5ZHNCNk1lZnh6MkIrUmRCRjJhU3NZdTE5dUtBcg0KS0QxOVNGSC9uMnVmZEJ6SG4wSEprOGZZR1J6QWpsc2VDVVF3WndJREFRQUJBb0lCQVFDbkNzTlpxOUY5Y3pEMg0KMmNzcXkxSEJJbWY1NDN2SndmSklVUHVONzhoWTV4dGxCREhCb2IzMFlxMTJrcEFUdC9tam9QVW04cjZhd1FUTQ0KRGhReXBxeWhRdWVzKy94dEZrY0U5eEpiZjVSSTMxUXQxN0dnK0lIbnlYck9zWWxxS1ZxeGw4LzNjMUVjVGZYeQ0KSjFhbmh4V0oxbjVQV3lFcHNNaE5waXF5VEZkMHBNTnNQbWlNekZlUFhmMDlmeEZWYVZhUExTTzF1UEh1VHRSdA0KVm1IeUlkaUdEdEdFWnBhbDVUQVhhZGcvd0UxSGl3OStUTHUySnJRSXRXaG00aVpsclhqWjZFazJMdUU2VFZlSg0KcXhMUjRBQUp2bDlBZ29HWWtQVWJNZjdHZXo0T2R6dThYTjVPOStOU3RTYlI2YU43aStNTzl1WVhTMUx2Kzc0Kw0KZXBJWGd2bFJBb0dCQVB3bE5jN2gxUkQ5cmN2Zk9BUis4QXJsUE5HWjlSeVVLNCtBV2pENUtuQ0dQK0dUQ3ZlUA0KbTVMUFNXLzNzS3hYVWw1QmZGL05KRFhuUlZQYmwyZDRvNUFTdVBVVEF5VXZHOW1tdWdnT0ZjZGM0S0EwK1MzcQ0KL2ZSMHZWRU5xSGhyc1kzdk5CLzlCamhoN25xaXJvWUFkY2JMZzJjWWpQNkJDVEZmbGZ4bUszWjVBb0dCQU11RQ0KNkJlNXVMZktNM3gzNDNxaG1uaGw2Y2RqTGwzUi9zT3J1ajA0cm5jbFpQQVFqdlV6UmVxNHhtV0loR2U5NEZSNA0KU09pcWRFUVZQcDBuQjV5SS9VK20xVFJPaHpWbThza1Q4cDJPSzk4b0pXR3pyNzJxc0M4aGpJOXNEZ2dsNm5ZMw0KdDMydVpBblIrMUZrTGsrTjZqTm9BRVNFalNxbENNTksvREtqYktYZkFvR0FiNnFMQ2ZRNXlDeVFxNWxQMWEzaA0KNFBGazNlNncvdGNmODQyRVkrdjFQNkEwNmxHVXFjNlB0NVRWa1NEQXZaSnVpQSs0WlRVVXRFcVlDV3RXd2h4TA0KVTZMM0JwSkU4bExLb3JtVDZiMVRKOWVhSTFsU2dXTncxTEplcFdiSEZZMmNOSitiRmcrWWtaL05YY0p1U0Nvcg0KL3I1aWsyWHNDMHBhSitPTktScVdaUUVDZ1lCZ29MM0JaZ0I1NHBzSFliU3pxTDY2bzBpWHpsTlpZRGJobUV0WQ0KZmV6M3pOMWJ6Y0RTVW9IRHErOG1qZWF2aXN0VHo3aHVIMkFNWXpuVFM1Q2xsYlVQZUZxSjl5N2kvL29OMWxhKw0KejUyczJsYkZTSmNNS2xwMFJpMkNldjgraHlJRzl2VTd5dXpjYk1JeUpxcUdRdzhMVVRtdlRtL242MnQ1cmNTSQ0KRm1lamFRS0JnRnp4OVNnRW5qMVhMWG5rNEtGbHp2NGcwcUF1NndpaFBCd3hraDFjVzVXcGN0emkreEhYWmd5eA0KUkxQMXVveWdkUVZ3RWg3STVrbHRFd2FISVk0NnBYaEJxZldCQ3FuTDNXYkpTOVlBUTRSWmd1NmlORnh5czJyNQ0Kb2p0SXRjTStydjJOeUlwcDVoU29BdVlyaUJINHNTYUFEY0lJN1pSaWkxeEpHV1E0WkVYSg0KLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0=",
	"grafana_id":      "admin@acornsoft.io",
	"grafana_passwd":  "admin0000",
}

type ClusterState int

const (
	CLUSTER_APPLIED ClusterState = 1 + iota
	CLUSTER_APPLYING
	CLUSTER_CREATED
	CLUSTER_CREATING
	CLUSTER_DELETED
	CLUSTER_DESTROYING
	CLUSTER_RESIZING
	CLUSTER_SCALEINED
	CLUSTER_SCALEINING
	DELETED
	DELETING
	DONE
	ERROR_CLUSTER_CREATE
	ERROR_CLUSTER_RESIZE
	ERROR_DELETE
	ERROR_INFRA_CREATE
	ERROR_INFRA_RESIZE
	ERROR_UPGRADE
	INFRA_APPLIED
	INFRA_APPLYING
	INFRA_CREATED
	INFRA_CREATING
	INFRA_DESTROYING
	INFRA_DESTROYED
	INFRA_ERROR
	INFRA_RESIZING
	INFRA_SCALEINED
	INFRA_SCALEINING
	RUNNING
	STOPPED
	UPGRADING
)

var states = [...]string{
	"CLUSTER_APPLIED",
	"CLUSTER_APPLYING",
	"CLUSTER_CREATED",
	"CLUSTER_CREATING",
	"CLUSTER_DELETED",
	"CLUSTER_DESTROYING",
	"CLUSTER_RESIZING",
	"CLUSTER_SCALEINED",
	"CLUSTER_SCALEINING",
	"DELETED",
	"DELETING",
	"DONE",
	"ERROR_CLUSTER_CREATE",
	"ERROR_CLUSTER_RESIZE",
	"ERROR_DELETE",
	"ERROR_INFRA_CREATE",
	"ERROR_INFRA_RESIZE",
	"ERROR_UPGRADE",
	"INFRA_APPLIED",
	"INFRA_APPLYING",
	"INFRA_CREATED",
	"INFRA_CREATING",
	"INFRA_DESTROYING",
	"INFRA_DESTROYED",
	"INFRA_ERROR",
	"INFRA_RESIZING",
	"INFRA_SCALEINED",
	"INFRA_SCALEINING",
	"RUNNING",
	"STOPPED",
	"UPGRADING",
}

func (m ClusterState) String() string { return states[m-1] }
