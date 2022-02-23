package utils

import (
	"bufio"
	cryptornad "crypto/rand"
	"fmt"
	"github.com/briandowns/spinner"
	"github.com/hhkbp2/go-logging"
	"kore-on/pkg/conf"
	"kore-on/pkg/model"
	"reflect"
	"runtime"
	"strconv"

	//"github.com/magiconair/properties"
	"github.com/pelletier/go-toml"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"math/big"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var logger = logging.GetLogger("utils")
var Spnr = spinner.New(spinner.CharSets[9], 100*time.Millisecond)

var knownProviders = []string{
	"gcp",
	"azure",
	"aws",
	"onpremise",
	"aliyun",
	"eks",
	"aks",
	"gke",
	"tke",
	"tencent",
	"diamanti",
}

var localProviders = []string{
	"virtualbox",
	"minikube",
}

func FileExists(name string) bool {
	//workDir, _ := os.Getwd()
	//fmt.Printf("workdir %s\n",workDir)
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}

	return true
}

func FileSizeAndExists(name string) (int64, bool, error) {
	//workDir, _ := os.Getwd()
	//fmt.Printf("workdir %s\n",workDir)
	var size int64 = 0
	stat, err := os.Stat(name)
	if err != nil {
		if os.IsNotExist(err) {
			return size, false, err
		}
	}
	size = stat.Size()

	return size, true, nil
}

func CopyFile(source string, dest string) (err error) {
	//fmt.Printf("copy file source %s dest %s \n",source, dest)
	sourcefile, err := os.Open(source)
	if err != nil {
		return err
	}

	defer sourcefile.Close()

	destfile, err := os.Create(dest)
	if err != nil {
		fmt.Printf("error %s\n", err)
		return err
	}

	defer destfile.Close()

	_, err = io.Copy(destfile, sourcefile)
	if err == nil {
		sourceinfo, err := os.Stat(source)

		if err == nil {
			err = os.Chmod(dest, sourceinfo.Mode())
		} else {
			return err
		}
	} else {
		return err
	}

	return nil
}

func CopyFile0600(source string, dest string) (err error) {
	sourcefile, err := os.Open(source)
	if err != nil {
		return err
	}

	defer sourcefile.Close()

	destfile, err := os.Create(dest)
	if err != nil {
		return err
	}

	defer destfile.Close()

	_, err = io.Copy(destfile, sourcefile)
	if err == nil {
		err = os.Chmod(dest, 0600)
	} else {
		return err
	}

	return nil
}

func CopyDir(source string, dest string) (err error) {

	// get properties of source dir
	sourceinfo, err := os.Stat(source)
	if err != nil {
		return err
	}

	// create dest dir

	err = os.MkdirAll(dest, sourceinfo.Mode())
	if err != nil {
		return err
	}

	directory, _ := os.Open(source)

	objects, err := directory.Readdir(-1)

	for _, obj := range objects {

		sourcefilepointer := source + "/" + obj.Name()

		destinationfilepointer := dest + "/" + obj.Name()

		if obj.IsDir() {
			// create sub-directories - recursively
			err = CopyDir(sourcefilepointer, destinationfilepointer)
			if err != nil {
				logger.Error(err)
			}
		} else {
			// perform copy
			err = CopyFile(sourcefilepointer, destinationfilepointer)
			if err != nil {
				logger.Error(err)
			}
		}

	}
	return
}

func ReadFile(filePath string, buf *[]byte) {

	file, err := os.Open(filePath)
	CheckError(err)

	defer file.Close()

	fi, err := file.Stat()
	CheckError(err)

	*buf = make([]byte, fi.Size())

	_, err = file.Read(*buf)
	CheckError(err)
}

func WriteFile(filePath string, buf *[]byte) error {
	f, err := os.OpenFile(filePath, os.O_RDWR, 0644)
	if err != nil {
		logger.Errorf("error while open file: %s\n", err.Error())
		return err
	}
	defer f.Close()

	err = f.Truncate(0)
	if err != nil {
		logger.Errorf("fail to write file[1]: %s\n", err.Error())
		return err
	}

	_, err = f.WriteString(string(*buf))
	if err != nil {
		logger.Errorf("fail to write file[2]: %s\n", err.Error())
		return err
	}

	return nil
}

func WriteFileString(filePath string, content string) error {
	f, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		logger.Errorf("error while open file: %s\n", err.Error())
		return err
	}
	defer f.Close()

	err = f.Truncate(0)
	if err != nil {
		logger.Errorf("fail to write file[1]: %s\n", err.Error())
		return err
	}

	_, err = f.WriteString(content)
	if err != nil {
		logger.Errorf("fail to write file[2]: %s\n", err.Error())
		return err
	}

	return nil
}

func CheckError(err error) {
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}

func CheckErrorWithMsg(err error, msg string) {
	if err != nil {
		logger.Error(err.Error())
		logger.Error(msg)
	}
}

func CheckProvider(p string) error {
	found := false

	for _, known := range knownProviders {
		if p == known {
			found = true
			break
		}
	}

	if !found {
		providers := strings.Join(knownProviders, ",")
		return fmt.Errorf("unrecognized provider \"%s\": known provider are %s", p, providers)
	}

	return nil
}

func CheckLocalProvider(p string) bool {

	for _, known := range localProviders {
		if p == known {
			return true
		}
	}

	return false
}

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func checkIp(public string, private string) error {
	r, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)
	if len(public) == 0 {
		return fmt.Errorf("public ip of node not exists")
	} else if !r.MatchString(public) {
		return fmt.Errorf("public ip invalid: %s\n", public)
	}
	if len(private) == 0 {
		return fmt.Errorf("private ip of node not exists")
	} else if !r.MatchString(private) {
		return fmt.Errorf("private ip invalid: %s\n", private)
	}

	return nil
}

func ParentPath() string {
	wd, err := os.Getwd()
	if err != nil {
		PrintError(err.Error())
		os.Exit(1)
	}
	parent := filepath.Dir(wd)
	return parent
}

func CopyFilePreWork(workDir string, koreonToml model.KoreonToml, cmd string) error {

	errorCnt := 0

	os.MkdirAll(conf.KoreonDestDir, os.ModePerm)

	idRsa := workDir + "/" + conf.KoreonDestDir + "/" + "id_rsa"
	sslRegistryCrt := workDir + "/" + conf.KoreonDestDir + "/" + "ssl_registry.crt"
	sslRegistryKey := workDir + "/" + conf.KoreonDestDir + "/" + "ssl_registry.key"
	nodePoolSecurityPrivateKeyPath := koreonToml.NodePool.Security.PrivateKeyPath

	isPrivateRegistryPublicCert := koreonToml.PrivateRegistry.PublicCert
	regiSslCert := koreonToml.PrivateRegistry.CertFile.SslCertificate
	regiSslCertKey := koreonToml.PrivateRegistry.CertFile.SslCertificateKey

	switch cmd {
	case "create", "apply", "destroy":
		if !FileExists(nodePoolSecurityPrivateKeyPath) {
			PrintError(fmt.Sprintf("private-key-path : %s file is not found", nodePoolSecurityPrivateKeyPath))
			errorCnt++
		}
	default:
	}

	//레지스트리 설치 여부
	if koreonToml.PrivateRegistry.Install {
		//레지스트리 공인 인증서 사용하는 경우 인증서 파일이 있어야 함.
		if isPrivateRegistryPublicCert && cmd == "create" {

			if !FileExists(regiSslCert) {
				PrintError(fmt.Sprintf("registry ssl-certificate : %s file is not found", regiSslCert))
				errorCnt++
			}

			if !FileExists(regiSslCertKey) {
				PrintError(fmt.Sprintf("registry ssl-certificate-key : %s file is not found", regiSslCertKey))
				errorCnt++
			}
		}
		//close_network은 추후 처리
	}

	if errorCnt > 0 {
		os.Exit(1)
	} else {
		//상단은 validation check 만 진행하고 실제 복사등의 기능 구현은 여기애서 함.
		os.Remove(idRsa)
		os.Remove(sslRegistryCrt)
		os.Remove(sslRegistryKey)

		CopyFile0600(koreonToml.NodePool.Security.PrivateKeyPath, idRsa) //private-key-path copy

		if isPrivateRegistryPublicCert && cmd == "create" {
			CopyFile0600(regiSslCert, sslRegistryCrt)
			CopyFile0600(regiSslCertKey, sslRegistryKey)
		}
	}
	return nil
}

func GetCubeToml(workDir string) (model.KoreonToml, error) {
	var koreonToml = model.KoreonToml{}

	if !FileExists(conf.KoreonConfigFile) {
		//utils.PrintError("cube.toml file is not found. Run cube init first")
		return koreonToml, fmt.Errorf("file is not found")
	}

	c, err := ioutil.ReadFile(workDir + "/" + conf.KoreonConfigFile)
	if err != nil {
		//PrintError(err.Error())
		return koreonToml, err
	}

	str := string(c)
	str = strings.Replace(str, "\\", "/", -1)
	c = []byte(str)

	err = toml.Unmarshal(c, &koreonToml)
	if err != nil {
		PrintError(err.Error())
		return koreonToml, err
	}

	return koreonToml, nil
}

func CheckDocker() error {
	//fmt.Println("Checking pre-requisition [" + runtime.GOOS + "]")
	_, err := exec.Command("docker", "-v").Output()

	if err != nil {
		//fmt.Println(err.Error())
		PrintError("docker is not found. Install docker before proceeding")
		PrintError("Visit https://www.docker.com/get-started")
		return err
	}
	return nil
}

// AddressRange returns the first and last addresses in the given CIDR range.
func AddressRange(network *net.IPNet) (net.IP, net.IP) {
	// the first IP is easy
	firstIP := network.IP

	// the last IP is the network address OR NOT the mask address
	prefixLen, bits := network.Mask.Size()
	if prefixLen == bits {
		// Easy!
		// But make sure that our two slices are distinct, since they
		// would be in all other cases.
		lastIP := make([]byte, len(firstIP))
		copy(lastIP, firstIP)
		return firstIP, lastIP
	}

	firstIPInt, bits := ipToInt(firstIP)
	hostLen := uint(bits) - uint(prefixLen)
	lastIPInt := big.NewInt(1)
	lastIPInt.Lsh(lastIPInt, hostLen)
	lastIPInt.Sub(lastIPInt, big.NewInt(1))
	lastIPInt.Or(lastIPInt, firstIPInt)

	return firstIP, intToIP(lastIPInt, bits)
}

func ipToInt(ip net.IP) (*big.Int, int) {
	val := &big.Int{}
	val.SetBytes([]byte(ip))
	if len(ip) == net.IPv4len {
		return val, 32
	} else if len(ip) == net.IPv6len {
		return val, 128
	} else {
		panic(fmt.Errorf("Unsupported address length %d", len(ip)))
	}
}

func intToIP(ipInt *big.Int, bits int) net.IP {
	ipBytes := ipInt.Bytes()
	ret := make([]byte, bits/8)
	// Pack our IP bytes into the end of the return array,
	// since big.Int.Bytes() removes front zero padding.
	for i := 1; i <= len(ipBytes); i++ {
		ret[len(ret)-i] = ipBytes[len(ipBytes)-i]
	}
	return net.IP(ret)
}

func getServiceIP(cidr string, nextStep byte) string {

	_, ipv4Net, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Printf(err.Error())
	}
	startIp, _ := AddressRange(ipv4Net)
	//fmt.Println(fmt.Sprintf("start ip %s", startIp))

	startIp[3] = startIp[3] + nextStep
	//fmt.Printf("start ip %s %v\n", startIp, nextStep)

	return fmt.Sprintf("%s", startIp)

}

func PrintInfo(message string) {
	spData := strings.Split(message, "\n")
	if len(spData) > 0 {
		for i := 0; i < len(spData); i++ {
			fmt.Fprintf(os.Stdout, "%s\n", spData[i])
		}
	} else {
		fmt.Fprintf(os.Stdout, "%s\n", message)
	}
}

//
//2022.02.18 사용하는 함수
//
//

func PrintError(message string) {
	fmt.Fprintf(os.Stderr, "%s\n", message)
}

func CreateInventoryFile(destDir string, koreonToml model.KoreonToml, addNodes map[string]string) string {

	inventory := "# Inventory create by cube\n\n"

	masterIps := koreonToml.NodePool.Master.IP
	nodeIps := koreonToml.NodePool.Node.IP
	registryIp := koreonToml.PrivateRegistry.RegistryIP
	storageIp := koreonToml.SharedStorage.StorageIP
	etcdIps := koreonToml.Kubernetes.Etcd.IP

	masterPrivateIps := koreonToml.NodePool.Master.PrivateIP
	nodePrivateIps := koreonToml.NodePool.Node.PrivateIP
	etcdPrivateIps := koreonToml.Kubernetes.Etcd.PrivateIP
	registryPrivateIp := koreonToml.PrivateRegistry.PrivateIP
	storagePrivateIp := koreonToml.SharedStorage.PrivateIP

	sshPort := 22
	nodeCnt := 0

	if koreonToml.NodePool.Security.SSHPort > 0 {
		sshPort = koreonToml.NodePool.Security.SSHPort
	}

	for i := 0; i < len(masterIps); i++ {
		ip := ""
		if len(masterPrivateIps) > 0 {
			ip = masterPrivateIps[i]
		} else {
			ip = masterIps[i]
		}
		inventory += fmt.Sprintf("master-%v ansible_ssh_host=%s ip=%s ansible_port=%v\n", masterIps[i], masterIps[i], ip, sshPort)
	}

	for j := 0; j < len(nodeIps); j++ {
		nodeCnt++
		ip := ""
		if len(nodePrivateIps) > 0 {
			ip = nodePrivateIps[j]
		} else {
			ip = nodeIps[j]
		}

		inventoryItem := []string{
			fmt.Sprintf("worker-%v ansible_ssh_host=%s ip=%s ansible_port=%v", nodeIps[j], nodeIps[j], ip, sshPort),
		}
		inventoryItem = append(inventoryItem, "\n")
		inventory += strings.Join(inventoryItem, " ")

		//inventory += fmt.Sprintf("worker-%v ansible_ssh_host=%s ip=%s ansible_port=%v labels=\"%v\" taints=\"%v\"\n", nodes[i].IP[j], nodes[i].IP[j], ip, sshPort, nodeLabels, nodeTaints)

	}

	for i := 0; i < len(etcdIps); i++ {
		ip := ""
		if len(etcdPrivateIps) > 0 {
			ip = etcdPrivateIps[i]
		} else {
			ip = etcdIps[i]
		}
		inventory += fmt.Sprintf("etcd-%v ansible_ssh_host=%s ip=%s ansible_port=%v\n", etcdIps[i], etcdIps[i], ip, sshPort)
	}

	if koreonToml.PrivateRegistry.Install {
		ip := ""
		if registryPrivateIp != "" {
			ip = registryPrivateIp
		} else {
			ip = registryIp
		}
		inventory += fmt.Sprintf("registry-%v ansible_ssh_host=%s ip=%s ansible_port=%v\n", registryIp, registryIp, ip, sshPort)
	}

	if koreonToml.SharedStorage.Install {
		ip := ""
		if storagePrivateIp != "" {
			ip = storagePrivateIp
		} else {
			ip = storageIp
		}
		inventory += fmt.Sprintf("storage-%v ansible_ssh_host=%s ip=%s ansible_port=%v\n", storageIp, storageIp, ip, sshPort)
	}

	//etcd
	inventory += fmt.Sprintf("\n")
	inventory += fmt.Sprintf("[etcd]\n")

	for i := 0; i < len(etcdIps); i++ {
		//inventory += fmt.Sprintf("etcd%02d\n", i+1)
		inventory += fmt.Sprintf("etcd-%v\n", etcdIps[i])
	}

	//etcd-private
	inventory += fmt.Sprintf("\n")
	inventory += fmt.Sprintf("[etcd-private]\n")

	for i := 0; i < len(etcdIps); i++ {
		//inventory += fmt.Sprintf("etcd%02d\n", i+1)
		inventory += fmt.Sprintf("etcd-%v\n", etcdIps[i])
	}

	//masters
	inventory += fmt.Sprintf("\n")
	inventory += fmt.Sprintf("[masters]\n")

	for i := 0; i < len(masterIps); i++ {
		//inventory += fmt.Sprintf("master%02d\n", i+1)
		inventory += fmt.Sprintf("master-%v\n", masterIps[i])
	}

	//sslhost
	inventory += fmt.Sprintf("\n")
	inventory += fmt.Sprintf("[sslhost]\n")
	//inventory += fmt.Sprintf("master01\n")

	if masterIps != nil {
		inventory += fmt.Sprintf("master-%v\n", masterIps[0])
	}

	//node
	nodeCnt = 0
	inventory += fmt.Sprintf("\n")
	inventory += fmt.Sprintf("[node]\n")

	if addNodes != nil && len(addNodes) > 0 {
		for ip, _ := range addNodes {
			//inventory += fmt.Sprintf("worker%02d\n", nodeCnt)
			inventory += fmt.Sprintf("worker-%v\n", ip)
		}
	} else {
		for j := 0; j < len(nodeIps); j++ {
			nodeCnt++
			//inventory += fmt.Sprintf("worker%02d\n", nodeCnt)
			inventory += fmt.Sprintf("worker-%v\n", nodeIps[j])
		}
	}
	//registry
	inventory += fmt.Sprintf("\n")
	inventory += fmt.Sprintf("[registry]\n")
	if koreonToml.PrivateRegistry.Install {
		if koreonToml.PrivateRegistry.Install {
			//inventory += fmt.Sprintf("registry01\n")
			inventory += fmt.Sprintf("registry-%v\n", registryIp)
		}
	}

	//storage
	inventory += fmt.Sprintf("\n")
	inventory += fmt.Sprintf("[storage]\n")
	if koreonToml.SharedStorage.Install {
		if koreonToml.SharedStorage.Install {
			//inventory += fmt.Sprintf("storage01\n")
			inventory += fmt.Sprintf("storage-%v\n", storageIp)
		}
	}
	//fmt.Printf("destDir =  %s\n", destDir)

	inventory += fmt.Sprintf("\n")
	inventory += fmt.Sprintf("[cluster:children]\n")
	inventory += fmt.Sprintf("masters\n")
	inventory += fmt.Sprintf("node\n")

	os.MkdirAll(destDir, os.ModePerm)

	ioutil.WriteFile(destDir+"/"+"inventory.ini", []byte(inventory), 0600)
	return destDir + "/" + "inventory.ini"
}

func CreateBasicYaml(destDir string, koreonToml model.KoreonToml) string {
	var allYaml = model.BasicYaml{}

	//default values
	allYaml.Provider = false
	allYaml.CloudProvider = "onpremise"

	allYaml.ServiceIPRange = "10.96.0.0/12"
	allYaml.PodIPRange = "10.32.0.0/12" // # FlannelNetwork와 동일"
	allYaml.InstallDir = "/var/lib/knit1"

	lbPort := 6443
	//extLbPort := 6443

	regiPath := fmt.Sprintf("%s/roles/registry/files", destDir)
	sshPath := fmt.Sprintf("%s/roles/master/files", destDir)
	allYamlPath := fmt.Sprintf("%s/group_vars/all", destDir)

	allYaml.ClusterName = koreonToml.Koreon.ClusterName

	clusterID, _ := NewUUID()

	allYaml.ClusterID = clusterID

	k8sVersion := koreonToml.Kubernetes.Version
	//providerName := koreonToml.NodePool.Provider.Name

	allYaml.DataRootDir = koreonToml.NodePool.DataDir

	isPrivateRegistryPubicCert := koreonToml.PrivateRegistry.PublicCert
	if isPrivateRegistryPubicCert {
		os.MkdirAll(regiPath, os.ModePerm)
		CopyFile(conf.KoreonDestDir+"/"+"ssl_registry.crt", regiPath+"/harbor.crt")
		CopyFile(conf.KoreonDestDir+"/"+"ssl_registry.key", regiPath+"/harbor.key")
	}

	os.MkdirAll(sshPath, os.ModePerm)
	CopyFile(conf.KoreonDestDir+"/"+"id_rsa", sshPath+"/id_rsa")
	CopyFile(conf.KoreonDestDir+"/"+"id_rsa.pub", sshPath+"/id_rsa.pub")

	//allYaml.Provider = koreonToml.Cube.Provider
	allYaml.ClosedNetwork = koreonToml.Koreon.ClosedNetwork
	//allYaml.CloudProvider = providerName
	allYaml.DataRootDir = koreonToml.NodePool.DataDir
	allYaml.K8SVersion = k8sVersion
	registryIP := koreonToml.PrivateRegistry.RegistryIP
	registryDomain := koreonToml.PrivateRegistry.RegistryIP

	if koreonToml.PrivateRegistry.RegistryDomain != "" {
		registryDomain = koreonToml.PrivateRegistry.RegistryDomain
	}

	if koreonToml.Koreon.ClosedNetwork {
		//allYaml.APIImage = registryDomain + "/google_containers/kube-apiserver-amd64:" + k8sVersion
		//allYaml.ControllerImage = registryDomain + "/google_containers/kube-controller-manager-amd64:" + k8sVersion
		//allYaml.SchedulerImage = registryDomain + "/google_containers/kube-scheduler-amd64:" + k8sVersion
	} else {
		//allYaml.APIImage = "k8s.gcr.io/kube-apiserver-amd64:" + k8sVersion
		//allYaml.ControllerImage = "k8s.gcr.io/kube-controller-manager-amd64:" + k8sVersion
		//allYaml.SchedulerImage = "k8s.gcr.io/kube-scheduler-amd64:" + k8sVersion
	}

	if koreonToml.Kubernetes.ServiceCidr != "" {
		allYaml.ServiceIPRange = koreonToml.Kubernetes.ServiceCidr
	}

	if koreonToml.Kubernetes.PodCidr != "" {
		allYaml.PodIPRange = koreonToml.Kubernetes.PodCidr
	}

	allYaml.LbPort = lbPort

	if len(koreonToml.NodePool.Master.PrivateIP) == len(koreonToml.NodePool.Master.IP) {
		allYaml.APILbIP = fmt.Sprintf("https://%s:%d", koreonToml.NodePool.Master.PrivateIP[0], allYaml.LbPort)
	} else {
		allYaml.APILbIP = fmt.Sprintf("https://%s:%d", koreonToml.NodePool.Master.IP[0], allYaml.LbPort)
	}

	if koreonToml.NodePool.Master.LbIP == "" {
		allYaml.LbIP = koreonToml.NodePool.Master.IP[0]
	} else {
		allYaml.LbIP = koreonToml.NodePool.Master.LbIP
	}

	//allYaml.ApiSans = koreonToml.Kubernetes.ApiSans

	allYaml.RegistryInstall = koreonToml.PrivateRegistry.Install
	allYaml.RegistryDataDir = koreonToml.PrivateRegistry.DataDir
	allYaml.Registry = registryIP
	allYaml.RegistryDomain = registryDomain
	allYaml.RegistryPublicCert = isPrivateRegistryPubicCert

	allYaml.Haproxy = koreonToml.NodePool.Master.HaproxyInstall //# Set False When Already Physical Loadbalancer Available"

	allYaml.NfsIP = koreonToml.SharedStorage.StorageIP
	allYaml.NfsVolumeDir = koreonToml.SharedStorage.VolumeDir

	allYaml.StorageInstall = koreonToml.SharedStorage.Install

	allYaml.MasterIsolated = koreonToml.NodePool.Master.Isolated

	//if koreonToml.Cube.StorageClassName != "" {
	//	allYaml.StorageClassName = koreonToml.Cube.StorageClassName
	//} else {
	//	allYaml.StorageClassName = "default-storage"
	//}

	//switch koreonToml.NodePool.Provider.Name {
	//case "aws", "eks":
	//	//todo 확인 필요 && koreonToml.Cube.Provider
	//	if koreonToml.SharedStorage.StorageType == "" {
	//		allYaml.StorageType = "efs"
	//	} else {
	//		allYaml.StorageType = koreonToml.SharedStorage.StorageType
	//	}
	//case "azure", "aks":
	//	//todo 확인필요 && koreonToml.Cube.Provider
	//	if koreonToml.SharedStorage.StorageType == "" {
	//		allYaml.StorageType = "azurefile"
	//	} else {
	//		allYaml.StorageType = koreonToml.SharedStorage.StorageType
	//	}
	//default:
	//	if koreonToml.SharedStorage.StorageType == "" {
	//		allYaml.StorageType = "nfs"
	//	} else {
	//		allYaml.StorageType = koreonToml.SharedStorage.StorageType
	//	}
	//}

	allYaml.LocalRepository = koreonToml.Koreon.LocalRepository

	allYaml.AuditLogEnable = koreonToml.Kubernetes.AuditLogEnable

	if koreonToml.Kubernetes.KubeProxyMode == "" {
		allYaml.KubeProxyMode = "iptables"
	} else {
		allYaml.KubeProxyMode = koreonToml.Kubernetes.KubeProxyMode
	}

	if koreonToml.Kubernetes.ContainerRuntime == "" {
		allYaml.ContainerRuntime = "docker"
	} else {
		allYaml.ContainerRuntime = koreonToml.Kubernetes.ContainerRuntime
	}

	if koreonToml.Koreon.CertValidityDays > 0 {
		allYaml.CertValidityDays = koreonToml.Koreon.CertValidityDays
	} else {
		allYaml.CertValidityDays = 3650
	}
	//vxlan-mode
	allYaml.KubeProxyMode = koreonToml.Kubernetes.KubeProxyMode
	b, _ := yaml.Marshal(allYaml)
	os.MkdirAll(allYamlPath, os.ModePerm)
	ioutil.WriteFile(allYamlPath+"/basic.yml", b, 0600)

	return allYamlPath + "/basic.yml"
}

func setField(field reflect.Value, defaultVal string) error {

	if !field.CanSet() {
		return fmt.Errorf("Can't set value\n")
	}

	switch field.Kind() {

	case reflect.Int:
		if val, err := strconv.ParseInt(defaultVal, 10, 64); err == nil {
			field.Set(reflect.ValueOf(int(val)).Convert(field.Type()))
		}
	case reflect.String:
		field.Set(reflect.ValueOf(defaultVal).Convert(field.Type()))
	}

	return nil
}

func Set(ptr interface{}, tag string) error {
	if reflect.TypeOf(ptr).Kind() != reflect.Ptr {
		return fmt.Errorf("Not a pointer")
	}

	v := reflect.ValueOf(ptr).Elem()
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		if defaultVal := t.Field(i).Tag.Get(tag); defaultVal != "-" {
			if err := setField(v.Field(i), defaultVal); err != nil {
				return err
			}

		}
	}
	return nil
}

func NewUUID() (string, error) {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(cryptornad.Reader, uuid)
	if n != len(uuid) || err != nil {
		return "", err
	}
	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80
	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

func CheckUserInput(prompt string, checkWord string) bool {
	var res string
	fmt.Print(prompt)

	reader := bufio.NewReader(os.Stdin)
	buf, _ := reader.ReadString('\n')

	if runtime.GOOS == "windows" {
		res = strings.Split(buf, "\r\n")[0]
	} else {
		res = strings.Split(buf, "\n")[0]
	}

	if res == checkWord {
		return true
	}

	return false
}
