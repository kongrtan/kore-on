package utils

import (
	"encoding/base64"
	"fmt"
	"github.com/pelletier/go-toml"
	"io/ioutil"
	"kore-on/pkg/conf"
	"kore-on/pkg/model"
	"os"
	"strings"
)

func GetKnitTomlConfig(workDir string) (model.KoreonToml, error) {

	errorCnt := 0
	configFullPath := workDir + "/" + conf.KoreonConfigFile
	//logger.Debugf("path : %s", configFullPath)

	envKoreonToml := os.Getenv("KOREON_TOML")

	var c []byte
	var err error

	if len(envKoreonToml) > 0 {
		//fmt.Println("envKoreonToml=" + envKoreonToml)
		c, err = base64.StdEncoding.DecodeString(envKoreonToml)
		ioutil.WriteFile("/cube/work/cube.toml", c, 0600)
	} else {
		if !FileExists(configFullPath) {
			PrintError(fmt.Sprintf("%s file is not found. Run cube init first", conf.KoreonConfigFile))
			os.Exit(1)
		}

		c, err = ioutil.ReadFile(configFullPath)
		if err != nil {
			PrintError(err.Error())
			os.Exit(1)
		}

		str := string(c)
		str = strings.Replace(str, "\\", "/", -1)
		c = []byte(str)
	}

	var koreonToml = model.KoreonToml{}
	err = toml.Unmarshal(c, &koreonToml)
	if err != nil {
		PrintError(err.Error())
		errorCnt++
	}

	return koreonToml, err
}

func ValidateKoreonTomlConfig(workDir string) (model.KoreonToml, bool) {
	errorCnt := 0
	koreonToml, _ := GetKnitTomlConfig(workDir)

	cubeVersion := koreonToml.Koreon.Version
	//cubeClusterName := koreonToml.Cube.ClusterName
	//cubeClusterDescription := koreonToml.Cube.ClusterDescription
	cubeClusterType := koreonToml.Koreon.ClusterType
	cubeClusterName := koreonToml.Koreon.ClusterName
	//cubeAlertLanguage := koreonToml.Cube.AlertLanguage

	cubeProvider := koreonToml.Koreon.Provider
	nodePoolDataDir := koreonToml.NodePool.DataDir
	nodePoolProviderName := koreonToml.NodePool.Provider.Name
	//nodePoolProviderLocation := koreonToml.NodePool.Provider.Location
	nodePoolSecuritySSHUserID := koreonToml.NodePool.Security.SSHUserID
	nodePoolSecurityPrivateKeyPath := koreonToml.NodePool.Security.PrivateKeyPath
	//nodePoolSecurityKeyPath := koreonToml.NodePool.Security.KeyPath

	//nodePoolMasterExternalLb := koreonToml.NodePool.Master.ExternalLb
	nodePoolMasterLbIP := koreonToml.NodePool.Master.LbIP

	kubernetesPodCidr := koreonToml.Kubernetes.PodCidr
	kubernetesServiceCidr := koreonToml.Kubernetes.ServiceCidr

	k8sVersion := koreonToml.Kubernetes.Version

	//apiSans := koreonToml.Kubernetes.ApiSans

	etcdCnt := len(koreonToml.Kubernetes.Etcd.IP)

	privateRegistryInstall := koreonToml.PrivateRegistry.Install
	privateRegistryRegistryIP := koreonToml.PrivateRegistry.RegistryIP
	privateRegistryDataDir := koreonToml.PrivateRegistry.DataDir
	isPrivateRegistryPublicCert := koreonToml.PrivateRegistry.PublicCert
	privateRegistryCrt := koreonToml.PrivateRegistry.CertFile.SslCertificate
	privateRegistryKey := koreonToml.PrivateRegistry.CertFile.SslCertificateKey

	if cubeVersion == "" {
		PrintError("cube > version is required.") //ssh-user-id 는 필수 값입니다.
		errorCnt++

		//todo 버전 체크 필요함.
	}

	if cubeClusterName == "" {
		PrintError("cube > cluster-name is required.")
		errorCnt++
		//todo 길이 체크
	}

	if koreonToml.Koreon.InstallDir != "" && !strings.HasPrefix(koreonToml.Koreon.InstallDir, "/") {
		PrintError("koreon > install-dir is Only absolute paths are supported.")
		errorCnt++
	}

	if k8sVersion == "" {
		PrintError("kubernetes > version is required.")
		errorCnt++
	} else if !IsSupportK8sVersion(k8sVersion) {
		PrintError(fmt.Sprintf("kubernetes > supported version: %v", conf.SupportK8SVersion))
		errorCnt++
	}

	if cubeProvider == true {

		switch nodePoolProviderName {
		case "aws":
			//todo aws vaildation
		case "azure":
			//todo azure vaildation
		default:
			PrintError("If the provider is true, only provider aws, azure is allowed.") //프로바이더가 true 인 경우에는 프로바이더 이름에 aws,azure만 사용 가능합니다.
			errorCnt++
		}
	} else {
		nodePoolMasterName := koreonToml.NodePool.Master.Name
		masterIpCnt := len(koreonToml.NodePool.Master.IP)

		if nodePoolMasterName == "" {
			//	PrintError("node-pool.master > name is required.")
			//	errorCnt++
		}

		nodePoolNodesIpCnt := len(koreonToml.NodePool.Node.IP)

		/*
			Large(HA) : 워커 노드 250대 이상, External ETCD 클러스터 구성, Shared Storage 이중화 옵션
			Medium(HA) : 워커 노드 10 ~ 250대 규모, Stacked ETCD 구성,  Shared Storage 이중화 옵션
			Small : 워커노드 10대 미만 규모, 단일 마스터(백업 구성), Shared Storage 이중화 구성(옵션)
			Tiny : Poc 또는 테스트 목적의 클러스터
			KaaS : 퍼블릭 프로바이더의 K8s as a Service 사용. 애드온과 인그레스 구성
		*/
		//fmt.Printf("masterIpCnt =%d\n", masterIpCnt)

		switch cubeClusterType {
		case "large":
			if masterIpCnt < 3 {
				PrintError("There are more then 3 master nodes.") //마스터 노드는 3개 이상 입니다.
				errorCnt++
			}

			if nodePoolNodesIpCnt < 250 {
				PrintError("There are more than 250 work nodes.") //워크 노드는 250개 이상 입니다.
				errorCnt++
			}

		case "medium":
			if masterIpCnt < 2 {
				PrintError("There are more then 2 master nodes.")
				errorCnt++
			}

			if nodePoolNodesIpCnt < 3 {
				PrintError("There are more than 10 work nodes.")
				errorCnt++
			}

		case "small":
			if masterIpCnt < 1 {
				PrintError("There are more then 1 master nodes.")
				errorCnt++
			}

		case "tiny":
			if masterIpCnt < 1 {
				PrintError("There are more then 1 master nodes.")
				errorCnt++
			}

		case "kaas":

		}

	}

	if nodePoolSecuritySSHUserID == "" && (!isKaas(nodePoolProviderName) || privateRegistryInstall) {
		PrintError("node-pool.security > ssh-user-id is required.") //ssh-user-id 는 필수 값입니다.
		errorCnt++
	}

	if nodePoolSecurityPrivateKeyPath == "" && (!isKaas(nodePoolProviderName) || privateRegistryInstall) {
		PrintError("node-pool.security > private-key-path is required.") //ssh-user-id 가 존재하지 않습니다.
		errorCnt++
	}

	if nodePoolMasterLbIP == "" {
		PrintError("node-pool.master > lb-ip is required.")
		errorCnt++
	}

	//if nodePoolMasterExternalLb == "" {
	//	PrintError("node-pool.master > external-lb is required.")
	//	errorCnt++
	//}

	if len(kubernetesPodCidr) > 0 {
		//todo check cilder
	}
	if len(kubernetesServiceCidr) > 0 {
		//todo check cilder
	}

	if !isKaas(nodePoolProviderName) {
		switch etcdCnt {
		case 1, 3, 5:
		default:
			PrintError("Only odd number of etcd nodes are supported.(1, 3, 5)")
			errorCnt++

		}
	}

	if len(nodePoolDataDir) > 0 {
		// todo node pool data dir check
	}

	//storage check
	switch koreonToml.NodePool.Provider.Name {
	default:
		cnt := checkSharedStorage(koreonToml)
		errorCnt += cnt
	}

	if privateRegistryInstall == true {

		if privateRegistryRegistryIP == "" {
			PrintError("private-registry > registry-ip is required.")
			errorCnt++
		}

		if privateRegistryDataDir == "" {
			PrintError("private-registry > data-dir is required.")
			errorCnt++
		}

		if isPrivateRegistryPublicCert {
			if privateRegistryCrt == "" {
				PrintError("private-registry.cert-file > ssl-certificate is required.")
				errorCnt++
			}

			if privateRegistryKey == "" {
				PrintError("private-registry.cert-file > ssl-certificate-key is required.")
				errorCnt++
			}
		}
	}

	if koreonToml.Koreon.ClosedNetwork {
		if koreonToml.Koreon.LocalRepository == "" && koreonToml.Koreon.LocalRepositoryArchiveFile == "" {
			PrintError("koreon> local-repository or local-repository-archive-file is required.")
			errorCnt++
		}

		if privateRegistryInstall {
			if koreonToml.PrivateRegistry.RegistryArchiveFile == "" {
				PrintError("private-registry >  registry-archive-file is required.")
				errorCnt++
			}
		}
	}

	if errorCnt > 0 {
		logger.Error("there are one or more errors")
		os.Exit(1)
		return koreonToml, false
	}
	return koreonToml, true
}

func isSupportLang(lang string) bool {
	result := false
	switch lang {
	case "ko", "ja", "en", "zh":
		result = true
	}
	return result
}

func checkSharedStorage(koreonToml model.KoreonToml) int {
	errorCnt := 0

	if koreonToml.SharedStorage.Install == true {

		if koreonToml.SharedStorage.VolumeDir == "" {
			PrintError("shared-storage > volume-dir is required.")
			errorCnt++
		}

		if koreonToml.SharedStorage.VolumeSize < 10 {
			PrintError("shared-storage > volume-size is 10 or more.")
			errorCnt++
		}

		//20200827
		if koreonToml.SharedStorage.StorageIP == "" {
			PrintError("shared-storage > storage-ip is required.")
			errorCnt++
		}

	}

	//20200827
	//if koreonToml.SharedStorage.StorageIP == "" {
	//	PrintError("shared-storage > storage-ip is required.")
	//	errorCnt++
	//}

	return errorCnt
}

func isKaas(providerName string) bool {
	result := false
	switch providerName {
	case "eks", "gke", "aks", "tke", "diamanti":
		result = true
	}
	return result
}
