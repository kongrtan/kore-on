package utils

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/pelletier/go-toml"
	"github.com/spf13/viper"
	"io/ioutil"
	"kore-on/pkg/conf"
	"kore-on/pkg/model"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Validation for cube.yaml
func ValidateCubeConfig(provider string) bool {
	errCnt := 0
	return true

	value := viper.GetString("alertmsg_lang")
	if len(value) == 0 {
		PrintError("alertmsg_lang is required")
		errCnt++
	} else if strings.Compare(value, "ko") != 0 && strings.Compare(value, "en") != 0 && strings.Compare(value, "ja") != 0 && strings.Compare(value, "zh") != 0 {
		PrintError(fmt.Sprintf("invalid alertmsg_lang value: %s", value))
		errCnt++
	}

	value = viper.GetString("cluster_id")
	if len(value) == 0 || len(value) > 50 {
		PrintError("cluster_id is required or less than 50 characters")
		errCnt++
	}

	value = viper.GetString("release_name")
	if len(value) == 0 {
		PrintError("release_name is required")
		errCnt++
	}

	value = viper.GetString("registry")
	if len(value) == 0 {
		PrintError("registry is required")
		errCnt++
	}

	if provider != "minikube" {
		//if !filepath.IsAbs(viper.GetString("private_key_path")) {
		//	PrintError("private_key_path should be absolute path")
		//	errCnt++
		//}
		//
		//if !filepath.IsAbs(viper.GetString("key_path")) {
		//	PrintError("key_path should be absolute path")
		//	errCnt++
		//}
	}

	switch provider {
	case "virtualbox":
		masterNodeCnt := len(viper.GetStringSlice("master_ip"))
		workerNodeCnt := len(viper.GetStringSlice("worker_ip"))

		if masterNodeCnt <= 0 || masterNodeCnt == 4 || masterNodeCnt == 6 || masterNodeCnt == 8 || masterNodeCnt > 9 {
			PrintError("num of master_ip should be odd number(5, 7, 9) if greater than 3 and lower than 10")
			errCnt++
		}

		if viper.GetInt("master_cpus") < 1 && viper.GetInt("master_cpus") > 16 {
			PrintError("master node cpu should be in 1~16")
			errCnt++
		}

		if viper.GetInt("master_memory") < 1024 || viper.GetInt("master_memory") > 8102 {
			PrintError("master node memory size should be greater than 1024 and lower than 8102")
			errCnt++
		}

		if workerNodeCnt > 0 && (viper.GetInt("worker_cpus") < 1 && viper.GetInt("worker_cpus") > 16) {
			PrintError("worker node cpu should be in 1~16")
			errCnt++
		}

		if workerNodeCnt > 0 && (viper.GetInt("worker_memory") < 1024 || viper.GetInt("worker_memory") > 8102) {
			PrintError("worker node memory size should be greater than 1024 and lower than 8102")
			errCnt++
		}

		if viper.GetString("haproxy") != "true" && viper.GetString("haproxy") != "false" {
			PrintError("haproxy should be true or false")
			errCnt++
		}
		if !viper.IsSet("nfs_ip") {
			PrintError("nfs_ip is required")
			errCnt++
		}
		if !viper.IsSet("nfs_mountdir") {
			PrintError("nfs_mountdir is required")
			errCnt++
		}

	case "minikube":
		if viper.GetInt("cpus") < 1 || viper.GetInt("cpus") > 16 {
			PrintError("number of cpu should be in 1~16")
			errCnt++
		}

		if viper.GetInt("memory") < 1024 || viper.GetInt("memory") > 8102 {
			PrintError("memory size should be greater than 1024 and lower than 8102")
			errCnt++
		}

		if !viper.IsSet("hyperv_switch_name") {
			PrintError("hyperv_switch_name is required")
			errCnt++
		}

		if !viper.IsSet("hyperv_switch_name") {
			PrintError("hyperv_switch_name is required")
			errCnt++
		}

	case "baremetal":
		if len(viper.GetStringSlice("master_ip")) == 0 {
			PrintError("master_ip is required")
			errCnt++
		} else if len(viper.GetStringSlice("master_ip")) == 4 || len(viper.GetStringSlice("master_ip")) == 6 || len(viper.GetStringSlice("master_ip")) == 8 || len(viper.GetStringSlice("master_ip")) > 9 {
			PrintError("num of master_ip should be odd number(5, 7, 9) if greater than 3 and lower than 10")
			errCnt++
		}

		if !viper.IsSet("haproxy") {
			PrintError("haproxy is required")
			errCnt++
		} else if viper.GetString("haproxy") != "true" && viper.GetString("haproxy") != "false" {
			PrintError("haproxy should be true or false")
			errCnt++
		}
		if !viper.IsSet("ssh_user_id") {
			PrintError("ssh_user_id is required")
			errCnt++
		}
		if !viper.IsSet("data_dir") {
			PrintError("data_dir is required")
			errCnt++
		}
		if !viper.IsSet("nfs_ip") {
			PrintError("nfs_ip is required")
			errCnt++
		}
		if !viper.IsSet("nfs_mountdir") {
			PrintError("nfs_mountdir is required")
			errCnt++
		}

	case "rovius":
		if !viper.IsSet("api_url") {
			PrintError("api_url is required")
			errCnt++
		}
		if !viper.IsSet("api_key") {
			PrintError("api_key is required")
			errCnt++
		}
		if !viper.IsSet("secret_key") {
			PrintError("secret_key is required")
			errCnt++
		}
		if !viper.IsSet("zone") {
			PrintError("zone is required")
			errCnt++
		}
		if !viper.IsSet("master_vm_size") {
			PrintError("master_vm_size is required")
			errCnt++
		}
		if !viper.IsSet("worker_vm_size") {
			PrintError("worker_vm_size is required")
			errCnt++
		}
		if !viper.IsSet("worker_node_count") {
			PrintError("worker_node_count is required")
			errCnt++
		}
		if !viper.IsSet("network_offering") {
			PrintError("network_offering is required")
			errCnt++
		}
		if !viper.IsSet("compute_template") {
			PrintError("compute_template is required")
			errCnt++
		}
		if !viper.IsSet("worker_vm_size") {
			PrintError("worker_vm_size is required")
			errCnt++
		}
		if !viper.IsSet("nfs_ip") {
			PrintError("nfs_ip is required")
			errCnt++
		}
		if !viper.IsSet("nfs_mountdir") {
			PrintError("nfs_mountdir is required")
			errCnt++
		}

	case "aws":
		masterNodeCnt := viper.GetInt("master_node_count")

		if awsAccountId := os.Getenv("AWS_ACCOUNT_ID"); awsAccountId == "" {
			PrintError("AWS_ACCOUNT_ID env should be set")
			errCnt++
		}

		if awsAccessKey := os.Getenv("AWS_ACCESS_KEY_ID"); awsAccessKey == "" {
			PrintError("AWS_ACCESS_KEY_ID env should be set")
			errCnt++
		}

		if awsSecretKey := os.Getenv("AWS_SECRET_ACCESS_KEY"); awsSecretKey == "" {
			PrintError("AWS_SECRET_ACCESS_KEY env should be set")
			errCnt++
		}

		if !viper.IsSet("region") {
			PrintError("region is required")
			errCnt++
		}
		if !viper.IsSet("availability_zone") {
			PrintError("availability_zone is required")
			errCnt++
		}

		if !viper.IsSet("master_vm_size") {
			PrintError("master_vm_size is required")
			errCnt++
		}
		if !viper.IsSet("master_vm_boot_storage_type") {
			PrintError("master_vm_boot_storage_type is required")
			errCnt++
		}
		if !viper.IsSet("master_vm_boot_storage_size") {
			PrintError("master_vm_boot_storage_size is required")
			errCnt++
		}
		if !viper.IsSet("master_vm_data_storage_type") {
			PrintError("master_vm_data_storage_type is required")
			errCnt++
		}
		if !viper.IsSet("master_vm_data_storage_size") {
			PrintError("master_vm_data_storage_size is required")
			errCnt++
		} else {
			if diskSize := viper.GetInt("master_vm_data_storage_size"); diskSize < 100 {
				PrintError("The data disk size of master instance must be at least 100G")
				errCnt++
			}
		}

		if !viper.IsSet("worker_vm_size") {
			PrintError("worker_vm_size is required")
			errCnt++
		}
		if !viper.IsSet("worker_vm_boot_storage_type") {
			PrintError("worker_vm_boot_storage_type is required")
			errCnt++
		}
		if !viper.IsSet("worker_vm_boot_storage_size") {
			PrintError("worker_vm_boot_storage_size is required")
			errCnt++
		}
		if !viper.IsSet("worker_vm_data_storage_type") {
			PrintError("worker_vm_data_storage_type is required")
			errCnt++
		}
		if !viper.IsSet("worker_vm_data_storage_size") {
			PrintError("worker_vm_data_storage_size is required")
			errCnt++
		} else {
			if diskSize := viper.GetInt("worker_vm_data_storage_size"); diskSize < 100 {
				PrintError("The data disk size of worker instance must be at least 100G")
				errCnt++
			}
		}

		if masterNodeCnt <= 0 || masterNodeCnt == 4 || masterNodeCnt == 6 || masterNodeCnt == 8 || masterNodeCnt > 9 {
			PrintError("num of master_ip should be odd number(5, 7, 9) if greater than 3 and lower than 10")
			errCnt++
		}

		if masterNodeCnt <= 0 || masterNodeCnt == 4 || masterNodeCnt == 6 || masterNodeCnt == 8 || masterNodeCnt > 9 {
			PrintError("num of master should be odd number(5, 7, 9) if greater than 3 and lower than 10")
			errCnt++
		}
		if !viper.IsSet("worker_node_count") {
			PrintError("worker_node_count is required")
			errCnt++
		}

	case "azure":
		validResPrefix, _ := regexp.Compile("^[a-zA-Z0-9-]*$")

		masterNodeCnt := viper.GetInt("master_node_count")

		if azureSubscriptionId := os.Getenv("AZURE_SUBSCRIPTION_ID"); azureSubscriptionId == "" {
			PrintError("AZURE_SUBSCRIPTION_ID env should be set")
			errCnt++
		}

		if azureClientId := os.Getenv("AZURE_CLIENT_ID"); azureClientId == "" {
			PrintError("AZURE_CLIENT_ID env should be set")
			errCnt++
		}

		if azureClientSecret := os.Getenv("AZURE_CLIENT_SECRET"); azureClientSecret == "" {
			PrintError("AZURE_CLIENT_SECRET env should be set")
			errCnt++
		}

		if azureTenantId := os.Getenv("AZURE_TENANT_ID"); azureTenantId == "" {
			PrintError("AZURE_TENANT_ID env should be set")
			errCnt++
		}

		if !viper.IsSet("location") {
			PrintError("location is required")
			errCnt++
		}
		if !viper.IsSet("resource_group") {
			PrintError("resource_group is required")
			errCnt++
		}

		if !validResPrefix.MatchString(viper.GetString("resource_group")) {
			PrintError("resource_group shouble alphanumeric characters and hyphens")
			errCnt++
		}

		if !viper.IsSet("master_vm_size") {
			PrintError("master_vm_size is required")
			errCnt++
		}
		if !viper.IsSet("master_vm_boot_storage_type") {
			PrintError("master_vm_boot_storage_type is required")
			errCnt++
		}
		if !viper.IsSet("master_vm_boot_storage_size") {
			PrintError("master_vm_boot_storage_size is required")
			errCnt++
		}
		if !viper.IsSet("master_vm_data_storage_type") {
			PrintError("master_vm_data_storage_type is required")
			errCnt++
		}
		if !viper.IsSet("master_vm_data_storage_size") {
			PrintError("master_vm_data_storage_size is required")
			errCnt++
		} else {
			if diskSize := viper.GetInt("master_vm_data_storage_size"); diskSize < 100 {
				PrintError("The data disk size of master instance must be at least 100G")
				errCnt++
			}
		}

		if !viper.IsSet("worker_vm_size") {
			PrintError("worker_vm_size is required")
			errCnt++
		}
		if !viper.IsSet("worker_vm_boot_storage_type") {
			PrintError("worker_vm_boot_storage_type is required")
			errCnt++
		}
		if !viper.IsSet("worker_vm_boot_storage_size") {
			PrintError("worker_vm_boot_storage_size is required")
			errCnt++
		}
		if !viper.IsSet("worker_vm_data_storage_type") {
			PrintError("worker_vm_data_storage_type is required")
			errCnt++
		}
		if !viper.IsSet("worker_vm_boot_storage_size") {
			PrintError("worker_vm_boot_storage_size is required")
			errCnt++
		} else {
			if diskSize := viper.GetInt("worker_vm_data_storage_size"); diskSize < 100 {
				PrintError("The data disk size of worker instance must be at least 100G")
				errCnt++
			}
		}

		if masterNodeCnt <= 0 || masterNodeCnt == 4 || masterNodeCnt == 6 || masterNodeCnt == 8 || masterNodeCnt > 9 {
			PrintError("num of master should be odd number(5, 7, 9) if greater than 3 and lower than 10")
			errCnt++
		}
		if !viper.IsSet("worker_node_count") {
			PrintError("worker_node_count is required")
			errCnt++
		}

		if !viper.IsSet("storage_account_type") {
			PrintError("storage_account_type is required")
			errCnt++
		}
		if !viper.IsSet("ssh_user_id") {
			PrintError("ssh_user_id is required")
			errCnt++
		}
	}

	if errCnt > 0 {
		logger.Error("there are one or more errors")

		return false
	}

	return true
}

func WriteConfigItem(filePath string, old string, new string) {
	read, err := ioutil.ReadFile(filePath)
	CheckError(err)

	newContents := strings.Replace(string(read), old, new, -1)

	err = ioutil.WriteFile(filePath, []byte(newContents), 0)
	CheckError(err)
}

func findItemIndexOfAnsibleConfig(name string, config []string) int {
	for i := 0; i < len(config); i++ {
		if strings.HasPrefix(config[i], name) {
			return i
		}
	}

	return -1
}

func makeAnsibleConfigItem(name string, value interface{}) string {
	line := ""
	switch value.(type) {
	case string:
		line = fmt.Sprintf("%s: \"%s\"", name, value.(string))
	default:
		line = fmt.Sprintf("%s: %v", name, value)
	}
	return line
}

func replaceOrAppend(name string, value interface{}, config []string) ([]string, int) {
	index := findItemIndexOfAnsibleConfig(name, config)
	if index == -1 {
		config = append(config, makeAnsibleConfigItem(name, value))
	} else {
		config[index] = makeAnsibleConfigItem(name, value)
	}

	return config, index
}

func SetSimpleAnsibleConfig(configPath string, items map[string]interface{}) (string, error) {
	if !FileExists(configPath) {
		return "", fmt.Errorf("ansible config file not found")
	}

	rawContent, err := ioutil.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("fail to read: %s\n", err.Error())
	}
	content := string(rawContent)

	for k, v := range items { // 실제 저장할 값으로 변환
		items[k] = fmt.Sprintf("%s: %v", k, v)
	}

	lines := strings.Split(content, "\n")
	buffer := bytes.Buffer{}
	for i := 0; i < len(lines); i++ {
		find := false
		if i > 0 {
			buffer.WriteString("\n")
		}

		index := strings.Index(lines[i], ":")
		if index == -1 { // item이 없는 줄
			buffer.WriteString(lines[i])
		} else {
			current := strings.TrimSpace(lines[i][:index])
			for k, v := range items {
				if strings.Compare(k, current) == 0 {
					index = strings.Index(lines[i], "#")
					if index == -1 { // 같은 줄에 주석이 없다.
						buffer.WriteString(v.(string))
					} else {
						buffer.WriteString(fmt.Sprintf("%s %s", v.(string), lines[i][index:]))
					}
					find = true
					delete(items, k)
					break
				}
			}

			if !find {
				buffer.WriteString(lines[i])
			}
		}
	}

	f, err := os.OpenFile(configPath, os.O_RDWR, 0644)
	if err != nil {
		return "", err
	}
	defer f.Close()

	f.Seek(0, 0)
	err = f.Truncate(0)
	if err != nil {
		return "", fmt.Errorf("fail to truncate: %s\n", err.Error())
	}

	_, err = f.WriteString(buffer.String())
	if err != nil {
		return "", fmt.Errorf("fail to write: %s\n", err.Error())
	}

	return content, nil
}

func SetCubeConfigAddon(configPath string, addonName string, value bool) (string, error) {
	if !FileExists(configPath) {
		return "", fmt.Errorf("cube config file not found")
	}

	rawContent, err := ioutil.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("fail to read: %s\n", err.Error())
	}

	content := string(rawContent)

	lines := strings.Split(content, "\n")
	buffer := bytes.Buffer{}
	for i := 0; i < len(lines); i++ {
		if i > 0 {
			buffer.WriteString("\n")
		}

		index := strings.Index(lines[i], ":")
		if index == -1 { // item이 없는 줄
			buffer.WriteString(lines[i])
		} else {
			n := strings.TrimSpace(lines[i][:index])
			if strings.Compare("addons", n) == 0 { // find add-on list
				logger.Debugf("find addons: %d", i)
				for ; i < len(lines); i++ {
					index = strings.Index(lines[i], "#")
					item := lines[i]
					if index > -1 {
						item = lines[i][:index]
					}

					if strings.Contains(item, addonName) {
						logger.Debugf("find addon: %d", i)
						if strings.Contains(item, "true") {
							buffer.WriteString(strings.Replace(lines[i], "true", strconv.FormatBool(value), 1))
						} else {
							buffer.WriteString(strings.Replace(lines[i], "false", strconv.FormatBool(value), 1))
						}
						break
					} else {
						buffer.WriteString(lines[i])
					}
					buffer.WriteString("\n")
				}
			} else {
				buffer.WriteString(lines[i])
			}
		}
	}

	f, err := os.OpenFile(configPath, os.O_RDWR, 0644)
	if err != nil {
		return "", err
	}
	defer f.Close()

	f.Seek(0, 0)
	err = f.Truncate(0)
	if err != nil {
		return "", fmt.Errorf("fail to truncate: %s\n", err.Error())
	}

	_, err = f.WriteString(buffer.String())
	if err != nil {
		return "", fmt.Errorf("fail to write: %s\n", err.Error())
	}

	return content, nil
}

func GetCubeTomlConfig(workDir string) (model.CubeToml, error) {

	errorCnt := 0
	configFullPath := workDir + "/" + conf.CubeConfigFile
	//logger.Debugf("path : %s", configFullPath)

	envCubeToml := os.Getenv("CUBE_TOML")

	var c []byte
	var err error

	if len(envCubeToml) > 0 {
		//fmt.Println("envCubeToml=" + envCubeToml)
		c, err = base64.StdEncoding.DecodeString(envCubeToml)
		ioutil.WriteFile("/cube/work/cube.toml", c, 0600)
	} else {
		if !FileExists(configFullPath) {
			PrintError(fmt.Sprintf("%s file is not found. Run cube init first", conf.CubeConfigFile))
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

	var cubeToml = model.CubeToml{}
	err = toml.Unmarshal(c, &cubeToml)
	if err != nil {
		PrintError(err.Error())
		errorCnt++
	}

	return cubeToml, err
}

func ValidateCubeTomlConfig(workDir string) (model.CubeToml, bool) {
	errorCnt := 0
	cubeToml, _ := GetCubeTomlConfig(workDir)

	cubeVersion := cubeToml.Cube.Version
	//cubeClusterName := cubeToml.Cube.ClusterName
	//cubeClusterDescription := cubeToml.Cube.ClusterDescription
	cubeClusterType := cubeToml.Cube.ClusterType
	cubeClusterID := cubeToml.Cube.ClusterID
	//cubeAlertLanguage := cubeToml.Cube.AlertLanguage

	cubeProvider := cubeToml.Cube.Provider
	nodePoolDataDir := cubeToml.NodePool.DataDir
	nodePoolProviderName := cubeToml.NodePool.Provider.Name
	//nodePoolProviderLocation := cubeToml.NodePool.Provider.Location
	nodePoolSecuritySSHUserID := cubeToml.NodePool.Security.SSHUserID
	nodePoolSecurityPrivateKeyPath := cubeToml.NodePool.Security.PrivateKeyPath
	//nodePoolSecurityKeyPath := cubeToml.NodePool.Security.KeyPath

	//nodePoolMasterExternalLb := cubeToml.NodePool.Master.ExternalLb
	nodePoolMasterInternalLb := cubeToml.NodePool.Master.InternalLb

	kubernetesPodCidr := cubeToml.Kubernetes.PodCidr
	kubernetesServiceCidr := cubeToml.Kubernetes.ServiceCidr
	k8sVersion := cubeToml.Kubernetes.Version
	//apiSans := cubeToml.Kubernetes.ApiSans

	etcdCnt := len(cubeToml.Kubernetes.Etcd.IP)

	privateRegistryInstall := cubeToml.PrivateRegistry.Install
	privateRegistryRegistryIP := cubeToml.PrivateRegistry.RegistryIP
	privateRegistryDataDir := cubeToml.PrivateRegistry.DataDir
	isPrivateRegistryPublicCert := cubeToml.PrivateRegistry.PublicCert
	privateRegistryCrt := cubeToml.PrivateRegistry.CertFile.SslCertificate
	privateRegistryKey := cubeToml.PrivateRegistry.CertFile.SslCertificateKey

	if cubeVersion == "" {
		PrintError("cube > version is required.") //ssh-user-id 는 필수 값입니다.
		errorCnt++

		//todo 버전 체크 필요함.
	}

	//if !cubeToml.Cube.DebugMode {
	//	isVerCheckPass := false
	//
	//	//2019.04.22 version 체크 확인
	//	url := "http://yum.acornsoft.io:8080/version/cube-version-v2.json"
	//	body := HttpGetVersion(http.MethodGet, url)
	//	//fmt.Printf("response = %s \n", string(body))
	//	//
	//	var responseVo model.CubeVersionV2
	//	err := json.Unmarshal(body, &responseVo)
	//	if err != nil {
	//		isVerCheckPass = true
	//		//fmt.Printf("error = %s \n", err)
	//		//os.Exit(1)
	//	} else {
	//		//여기부터
	//		for i := 0; i < len(responseVo); i++ {
	//			if responseVo[i].CubeVersion == cubeVersion {
	//				for j := 0; j < len(responseVo[i].Kubernetes); j++ {
	//					for k := 0; k < len(responseVo[i].Kubernetes[j].MinorVersion); k++ {
	//						if fmt.Sprintf("%s.%s", responseVo[i].Kubernetes[j].MajorVersion, responseVo[i].Kubernetes[j].MinorVersion[k]) == k8sVersion {
	//							isVerCheckPass = true
	//						}
	//					}
	//				}
	//			}
	//		}
	//
	//		if !isVerCheckPass {
	//			PrintError("\r\n cube.version > Unsupported Kubernetes version.")
	//			table := termtables.CreateTable()
	//			table.AddHeaders("cube > version", "Support Kubernetes Versions")
	//
	//			for i := 0; i < len(responseVo); i++ {
	//				//if responseVo[i].CubeVersion == cubeVersion {
	//				for j := 0; j < len(responseVo[i].Kubernetes); j++ {
	//					for k := 0; k < len(responseVo[i].Kubernetes[j].MinorVersion); k++ {
	//						table.AddRow(responseVo[i].CubeVersion, fmt.Sprintf("%s.%s", responseVo[i].Kubernetes[j].MajorVersion, responseVo[i].Kubernetes[j].MinorVersion[k]))
	//					}
	//				}
	//				//}
	//			}
	//			PrintError(fmt.Sprintln(table.Render()))
	//			errorCnt++
	//		}
	//	}
	//}

	//if cubeClusterName == "" {
	//	PrintError("cube > cluster-name is required.") //ssh-user-id 는 필수 값입니다.
	//	errorCnt++
	//}

	//if cubeClusterDescription == "" {
	//	PrintError("cube > cluster-description is required.") //ssh-user-id 는 필수 값입니다.
	//	errorCnt++
	//} else {
	//	switch cubeClusterType {
	//	case "large", "medium", "small", "tiny", "kaas":
	//	default:
	//		PrintError("cube > cluster-type supports only large, medium, small, tiny, kaas.")
	//		errorCnt++
	//	}
	//}

	if cubeClusterType == "" {
		PrintError("cube > cluster-type is required.")
		errorCnt++
		//todo 사이즈 체크
	}

	if cubeClusterID == "" {
		PrintError("cube > cluster-id is required.")
		errorCnt++
		//todo 길이 체크
	}

	//if cubeAlertLanguage == "" {
	//	PrintError("cube > alert-language is required.")
	//	errorCnt++
	//	// ko en
	//} else if !isSupportLang(cubeAlertLanguage) {
	//	PrintError(fmt.Sprintf("cube > invalid alertmsg_lang value: %s", cubeAlertLanguage))
	//	errorCnt++
	//}

	if cubeToml.Cube.InstallDir != "" && !strings.HasPrefix(cubeToml.Cube.InstallDir, "/") {
		PrintError("cube > install-dir is Only absolute paths are supported.")
		errorCnt++
	}

	if k8sVersion == "" {
		PrintError("kubernetes > version is required.")
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
		nodePoolMasterName := cubeToml.NodePool.Master.Name
		masterIpCnt := len(cubeToml.NodePool.Master.IP)
		nodePoolNodesCnt := len(cubeToml.NodePool.Nodes)

		if nodePoolMasterName == "" {
			//	PrintError("node-pool.master > name is required.")
			//	errorCnt++
		}

		nodePoolNodesIpCnt := 0
		for i := 0; i < nodePoolNodesCnt; i++ {
			nodePoolNodesIpCnt += len(cubeToml.NodePool.Nodes[i].IP)
			//if cubeToml.NodePool.Nodes[i].Name == "" {
			//	//PrintError(fmt.Sprintf("node-pool.node[%d] > name is required.", i))
			//	//errorCnt++
			//}
		}

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

	if nodePoolMasterInternalLb == "" {
		PrintError("node-pool.master > internal-lb is required.")
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
	switch cubeToml.NodePool.Provider.Name {
	case "aws", "eks":
		if cubeToml.SharedStorage.StorageType == "nas" || cubeToml.SharedStorage.StorageType == "nfs" {
			cnt := checkSharedStorage(cubeToml)
			errorCnt += cnt
		} else if cubeToml.SharedStorage.EfsFileSystemId == "" {
			PrintError("shared-storage > efs-file-system-id is required.")
			errorCnt++
		}
	case "azure", "aks":
		if cubeToml.SharedStorage.StorageType == "nas" || cubeToml.SharedStorage.StorageType == "nfs" {
			cnt := checkSharedStorage(cubeToml)
			errorCnt += cnt
		} else if cubeToml.SharedStorage.StorageAccount == "" {
			PrintError("shared-storage > storage-account is required.")
			errorCnt++
		}
	default:
		cnt := checkSharedStorage(cubeToml)
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
	/*
		if len(cubeToml.LiteEdge.Edge.IP) == 0 {
			PrintError("liteedge > edge > ip is required.")
			errorCnt++
		} else {
			isExist := false
			for i := 0; i < len(cubeToml.LiteEdge.Edge.IP); i++ {
				for j := 0; j < len(cubeToml.NodePool.Master.IP); j++ {
					if cubeToml.LiteEdge.Edge.IP[i] == cubeToml.NodePool.Master.IP[j] {
						isExist = true
						//	//	return
					}
				}

				if cubeToml.NodePool.Nodes != nil {
					for j := 0; j < len(cubeToml.NodePool.Nodes[0].IP); j++ {
						if cubeToml.LiteEdge.Edge.IP[i] == cubeToml.NodePool.Nodes[0].IP[j] {
							isExist = true
						}
					}
				}

			}

			for i := 0; i < len(cubeToml.LiteEdge.Edge.PrivateIP); i++ {
				for j := 0; j < len(cubeToml.NodePool.Master.PrivateIP); j++ {
					if cubeToml.LiteEdge.Edge.PrivateIP[i] == cubeToml.NodePool.Master.PrivateIP[j] {
						isExist = true
					}
				}

				if cubeToml.NodePool.Nodes != nil {
					for j := 0; j < len(cubeToml.NodePool.Nodes[0].PrivateIP); j++ {
						if cubeToml.LiteEdge.Edge.PrivateIP[i] == cubeToml.NodePool.Nodes[0].PrivateIP[j] {
							isExist = true
						}
					}
				}
			}

			if !isExist {
				PrintError("liteedge > edge > ip does not exist on the nodepool.master  or nodepool.nodes")
				errorCnt++
			}
		}

		if cubeToml.LiteEdge.Kakao.ApiKey != "" || cubeToml.LiteEdge.Kakao.SenderKey != "" {
			if cubeToml.LiteEdge.Kakao.ApiKey == "" || cubeToml.LiteEdge.Kakao.SenderKey == "" {
				PrintError("liteedge > kakao > api-key or sender-key does not exist. ")
				errorCnt++
			}
		}

		if cubeToml.LiteEdge.Mail.UserName != "" || cubeToml.LiteEdge.Mail.Password != "" || cubeToml.LiteEdge.Mail.Host != "" || cubeToml.LiteEdge.Mail.Port != 0 {
			if cubeToml.LiteEdge.Mail.UserName == "" || cubeToml.LiteEdge.Mail.Password == "" || cubeToml.LiteEdge.Mail.Host == "" || cubeToml.LiteEdge.Mail.Port == 0 {
				PrintError("liteedge > mail > host or port or username or password  does not exist. ")
				errorCnt++
			}
		}
	*/
	if errorCnt > 0 {
		logger.Error("there are one or more errors")
		os.Exit(1)
		return cubeToml, false
	}
	return cubeToml, true
}

func isSupportLang(lang string) bool {
	result := false
	switch lang {
	case "ko", "ja", "en", "zh":
		result = true
	}
	return result
}

func checkSharedStorage(cubeToml model.CubeToml) int {
	errorCnt := 0

	if cubeToml.SharedStorage.Install == true {

		if cubeToml.SharedStorage.VolumeDir == "" {
			PrintError("shared-storage > volume-dir is required.")
			errorCnt++
		}

		if cubeToml.SharedStorage.VolumeSize < 10 {
			PrintError("shared-storage > volume-size is 10 or more.")
			errorCnt++
		}

		//20200827
		if cubeToml.SharedStorage.StorageIP == "" {
			PrintError("shared-storage > storage-ip is required.")
			errorCnt++
		}

	}

	//20200827
	//if cubeToml.SharedStorage.StorageIP == "" {
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
