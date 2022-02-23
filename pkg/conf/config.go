package conf

var Version = "unknown_version"
var CommitId = "unknown_commitid"
var BuildDate = "unknown_builddate"

const (
	KoreonImageName      = "koreon"
	KoreonImage          = "regi.k3.acornsoft.io/k3lab/koreon:1.1.2"
	KoreonKubeConfigPath = "/etc/kubernetes/acloud"
	KoreonKubeConfig     = "acloud-client-kubeconfig"
	KoreonConfigFile     = "koreon.toml"
	KoreonDestDir        = ".koreon"

	CreateYaml        = "/koreon/scripts/cluster.yml"
	AddNodeYaml       = "/koreon/scripts/add-node.yml"
	RemoveNodeYaml    = "/koreon/scripts/remove-node.yml"
	UpgradeYaml       = "/koreon/scripts/upgrade.yml"
	ResetYaml         = "/koreon/scripts/reset.yml"
	PreDestroyYaml    = "/koreon/scripts/pre-destroy.yml"
	InventoryIni      = "/koreon/inventory/sample/inventory.ini"
	PrepareAirgapYaml = "/koreon/scripts/prepare-repository.yml"
	BasicYaml         = "/koreon/inventory/sample/group_vars/all/basic.yml"
	WorkDir           = "/koreon/work"
)

const (
	SUCCESS_FORMAT = "\033[1;32m%s\033[0m\n"
	STATUS_FORMAT  = "\033[1;32m%s\033[0m"
	ERROR_FORMAT   = "\x1B[1;3;31m%s\x1B[0m\n"
	CHECK_FORMAT   = "\033[1;34m%s\033[0m"
)
