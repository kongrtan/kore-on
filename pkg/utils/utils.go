package utils

import (
	"fmt"
	"github.com/briandowns/spinner"
	"github.com/hhkbp2/go-logging"
	"kore-on/pkg/conf"
	"kore-on/pkg/model"
	"reflect"
	"strconv"

	//"github.com/magiconair/properties"
	"github.com/pelletier/go-toml"
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

func CopyFilePreWork(workDir string, cubeToml model.CubeToml, cmd string) error {

	errorCnt := 0

	os.MkdirAll(conf.CubeDestDir, os.ModePerm)

	idRsa := workDir + "/" + conf.CubeDestDir + "/" + "id_rsa"

	sslCocktailCrt := workDir + "/" + conf.CubeDestDir + "/" + "ssl_cocktail.crt"
	sslCocktailKey := workDir + "/" + conf.CubeDestDir + "/" + "ssl_cocktail.key"
	sslRegistryCrt := workDir + "/" + conf.CubeDestDir + "/" + "ssl_registry.crt"
	sslRegistryKey := workDir + "/" + conf.CubeDestDir + "/" + "ssl_registry.key"

	harborBackupTgz := workDir + "/" + conf.CubeDestDir + "/" + "harbor-backup.tgz"

	nodePoolSecurityPrivateKeyPath := cubeToml.NodePool.Security.PrivateKeyPath

	isPrivateRegistryPublicCert := cubeToml.PrivateRegistry.PublicCert
	regiSslCert := cubeToml.PrivateRegistry.CertFile.SslCertificate
	regiSslCertKey := cubeToml.PrivateRegistry.CertFile.SslCertificateKey

	regiBackupFilePath := cubeToml.PrivateRegistry.BackupFilePath
	if cubeToml.PrivateRegistry.Install {
		if !FileExists(nodePoolSecurityPrivateKeyPath) {
			PrintError(fmt.Sprintf("private-key-path : %s file is not found", nodePoolSecurityPrivateKeyPath))
			errorCnt++
		}
	}

	if isPrivateRegistryPublicCert && cmd == "create" {

		if !FileExists(regiSslCert) && cubeToml.PrivateRegistry.Install {
			PrintError(fmt.Sprintf("registry ssl-certificate : %s file is not found", regiSslCert))
			errorCnt++
		}

		if !FileExists(regiSslCertKey) && cubeToml.PrivateRegistry.Install {
			PrintError(fmt.Sprintf("registry ssl-certificate-key : %s file is not found", regiSslCertKey))
			errorCnt++
		}

		if cubeToml.PrivateRegistry.Install {
			if regiBackupFilePath != "" && !FileExists(regiBackupFilePath) {
				PrintError(fmt.Sprintf("registry backup file %s is not found", regiBackupFilePath))
				errorCnt++
			}
		}
	}

	if errorCnt > 0 {
		os.Exit(1)
	} else {
		//os.Remove(idRsa)
		//os.Remove(idRsaPub)
		os.Remove(sslCocktailCrt)
		os.Remove(sslCocktailKey)
		os.Remove(sslRegistryCrt)
		os.Remove(sslRegistryKey)

		CopyFile0600(cubeToml.NodePool.Security.PrivateKeyPath, idRsa) //private-key-path copy
		//CopyFile0600(cubeToml.NodePool.Security.KeyPath, idRsaPub)     //keypath copy

		if isPrivateRegistryPublicCert && cmd == "create" {
			CopyFile0600(regiSslCert, sslRegistryCrt)
			CopyFile0600(regiSslCertKey, sslRegistryKey)
		}

		//파일이 없거나 파일 사이즈가 다른 경우만 복사함.
		if cubeToml.PrivateRegistry.Install {
			if regiBackupFilePath != "" && cmd == "create" {
				size2, _, err2 := FileSizeAndExists(regiBackupFilePath)
				if err2 != nil {
					PrintError(err2.Error())
					os.Exit(1)
				}
				size, isExist, _ := FileSizeAndExists(harborBackupTgz)
				if !isExist || (size != size2) {
					CopyFile0600(regiBackupFilePath, harborBackupTgz)
				}
			}
		}
	}
	return nil
}

func GetCubeToml(workDir string) (model.CubeToml, error) {
	var cubeToml = model.CubeToml{}

	if !FileExists(conf.CubeConfigFile) {
		//utils.PrintError("cube.toml file is not found. Run cube init first")
		return cubeToml, fmt.Errorf("file is not found")
	}

	c, err := ioutil.ReadFile(workDir + "/" + conf.CubeConfigFile)
	if err != nil {
		//PrintError(err.Error())
		return cubeToml, err
	}

	str := string(c)
	str = strings.Replace(str, "\\", "/", -1)
	c = []byte(str)

	err = toml.Unmarshal(c, &cubeToml)
	if err != nil {
		PrintError(err.Error())
		return cubeToml, err
	}

	return cubeToml, nil
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

func CreateInventoryFile(destDir string, cubeToml model.CubeToml) {

	inventory := "# Inventory create by cube\n\n"

	masterIps := cubeToml.NodePool.Master.IP
	nodes := cubeToml.NodePool.Nodes
	//edgeIps := cubeToml.LiteEdge.Edge.IP
	labels := cubeToml.NodePool.Labels
	registryIp := cubeToml.PrivateRegistry.RegistryIP
	storageIp := cubeToml.SharedStorage.StorageIP
	etcdIps := cubeToml.Kubernetes.Etcd.IP

	masterPrivateIps := cubeToml.NodePool.Master.PrivateIP
	//edgePrivateIps := cubeToml.LiteEdge.Edge.PrivateIP
	etcdPrivateIps := cubeToml.Kubernetes.Etcd.PrivateIP
	registryPrivateIp := cubeToml.PrivateRegistry.PrivateIP
	storagePrivateIp := cubeToml.SharedStorage.PrivateIP

	sshPort := 22
	nodeCnt := 0

	if cubeToml.NodePool.Security.SSHPort > 0 {
		sshPort = cubeToml.NodePool.Security.SSHPort
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

	for i := 0; i < len(nodes); i++ {
		for j := 0; j < len(nodes[i].IP); j++ {
			nodeCnt++
			ip := ""
			nodeLabels := ""
			nodeTaints := ""

			if len(nodes[i].PrivateIP) > 0 {
				ip = nodes[i].PrivateIP[j]
			} else {
				ip = nodes[i].IP[j]
			}

			inventoryItem := []string{
				fmt.Sprintf("worker-%v ansible_ssh_host=%s ip=%s ansible_port=%v", nodes[i].IP[j], nodes[i].IP[j], ip, sshPort),
			}

			for n := 0; n < len(labels); n++ {
				for m := 0; m < len(labels[n].IP); m++ {
					if nodes[i].IP[j] == labels[n].IP[m] {
						nodeLabels = strings.Join(labels[n].Labels, ",")
						nodeTaints = strings.Join(labels[n].Taints, ",")
					}
				}
			}

			if len(nodeLabels) > 0 {
				inventoryItem = append(inventoryItem, fmt.Sprintf("labels=\"%v\"", nodeLabels))
			}

			if len(nodeTaints) > 0 {
				inventoryItem = append(inventoryItem, fmt.Sprintf("taints=\"%v\"", nodeTaints))
			}

			inventoryItem = append(inventoryItem, "\n")

			inventory += strings.Join(inventoryItem, " ")

			//inventory += fmt.Sprintf("worker-%v ansible_ssh_host=%s ip=%s ansible_port=%v labels=\"%v\" taints=\"%v\"\n", nodes[i].IP[j], nodes[i].IP[j], ip, sshPort, nodeLabels, nodeTaints)
		}
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

	if cubeToml.PrivateRegistry.Install {
		ip := ""
		if registryPrivateIp != "" {
			ip = registryPrivateIp
		} else {
			ip = registryIp
		}
		inventory += fmt.Sprintf("registry-%v ansible_ssh_host=%s ip=%s ansible_port=%v\n", registryIp, registryIp, ip, sshPort)
	}

	if cubeToml.SharedStorage.Install {
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

	gpuNodeCnt := 0
	multiNicCnt := 0
	gpuNodeList := "\n[gpu-node]\n"
	multiNicList := "\n[multi-nic-node]\n"

	for i := 0; i < len(nodes); i++ {
		for j := 0; j < len(nodes[i].IP); j++ {
			nodeCnt++
			//inventory += fmt.Sprintf("worker%02d\n", nodeCnt)
			inventory += fmt.Sprintf("worker-%v\n", nodes[i].IP[j])

			for k := 0; k < len(nodes[i].NodeOptions); k++ {
				switch nodes[i].NodeOptions[k] {
				case "gpu":
					gpuNodeList += fmt.Sprintf("worker-%v\n", nodes[i].IP[j])
					gpuNodeCnt++
				case "multi-nic":
					multiNicList += fmt.Sprintf("worker-%v\n", nodes[i].IP[j])
					multiNicCnt++
				}
			}
		}
	}

	//registry
	inventory += fmt.Sprintf("\n")
	inventory += fmt.Sprintf("[registry]\n")
	if cubeToml.PrivateRegistry.Install {
		if cubeToml.PrivateRegistry.Install {
			//inventory += fmt.Sprintf("registry01\n")
			inventory += fmt.Sprintf("registry-%v\n", registryIp)
		}
	}

	//storage
	inventory += fmt.Sprintf("\n")
	inventory += fmt.Sprintf("[storage]\n")
	if cubeToml.SharedStorage.Install {
		if cubeToml.SharedStorage.Install {
			//inventory += fmt.Sprintf("storage01\n")
			inventory += fmt.Sprintf("storage-%v\n", storageIp)
		}
	}
	//fmt.Printf("destDir =  %s\n", destDir)

	os.MkdirAll(destDir, os.ModePerm)

	ioutil.WriteFile(destDir+"/"+"inventory.ini", []byte(inventory), 0600)

}

func CreateBasicYaml(destDir string, cubeToml model.CubeToml) {
	var allYaml = model.BasicYaml{}
	lbPort := 6443
	//extLbPort := 6443

	regiPath := fmt.Sprintf("%s/roles/registry/files", destDir)
	sshPath := fmt.Sprintf("%s/roles/master/files", destDir)
	allYamlPath := fmt.Sprintf("%s/group_vars/all", destDir)

	k8sVersion := cubeToml.Kubernetes.Version
	//providerName := cubeToml.NodePool.Provider.Name

	isPrivateRegistryPubicCert := cubeToml.PrivateRegistry.PublicCert
	if isPrivateRegistryPubicCert {
		os.MkdirAll(regiPath, os.ModePerm)
		CopyFile(conf.CubeDestDir+"/"+"ssl_registry.crt", regiPath+"/harbor.crt")
		CopyFile(conf.CubeDestDir+"/"+"ssl_registry.key", regiPath+"/harbor.key")
	}

	os.MkdirAll(sshPath, os.ModePerm)
	CopyFile(conf.CubeDestDir+"/"+"id_rsa", sshPath+"/id_rsa")
	CopyFile(conf.CubeDestDir+"/"+"id_rsa.pub", sshPath+"/id_rsa.pub")

	//allYaml.Provider = cubeToml.Cube.Provider
	allYaml.ClosedNetwork = cubeToml.Cube.ClosedNetwork
	//allYaml.CloudProvider = providerName
	allYaml.DataRootDir = cubeToml.NodePool.DataDir
	allYaml.K8SVersion = k8sVersion
	registryIP := cubeToml.PrivateRegistry.RegistryIP
	registryDomain := cubeToml.PrivateRegistry.RegistryIP

	if cubeToml.PrivateRegistry.RegistryDomain != "" {
		registryDomain = cubeToml.PrivateRegistry.RegistryDomain
	}

	if cubeToml.Cube.ClosedNetwork {
		//allYaml.APIImage = registryDomain + "/google_containers/kube-apiserver-amd64:" + k8sVersion
		//allYaml.ControllerImage = registryDomain + "/google_containers/kube-controller-manager-amd64:" + k8sVersion
		//allYaml.SchedulerImage = registryDomain + "/google_containers/kube-scheduler-amd64:" + k8sVersion
	} else {
		//allYaml.APIImage = "k8s.gcr.io/kube-apiserver-amd64:" + k8sVersion
		//allYaml.ControllerImage = "k8s.gcr.io/kube-controller-manager-amd64:" + k8sVersion
		//allYaml.SchedulerImage = "k8s.gcr.io/kube-scheduler-amd64:" + k8sVersion
	}

	allYaml.ClusterID = cubeToml.Cube.ClusterID

	allYaml.ServiceIPRange = "10.96.0.0/12"
	if cubeToml.Kubernetes.ServiceCidr != "" {
		allYaml.ServiceIPRange = cubeToml.Kubernetes.ServiceCidr
	}

	allYaml.PodIPRange = "10.32.0.0/12" // # FlannelNetwork와 동일"
	if cubeToml.Kubernetes.PodCidr != "" {
		allYaml.PodIPRange = cubeToml.Kubernetes.PodCidr
	}

	allYaml.LbPort = lbPort

	if cubeToml.NodePool.Master.InternalLb == "" {
		allYaml.APILbIP = fmt.Sprintf("https://%s:%d", cubeToml.NodePool.Master.IP[0], allYaml.LbPort)
		allYaml.LbIP = cubeToml.NodePool.Master.IP[0]
	} else {
		allYaml.APILbIP = fmt.Sprintf("https://%s:%d", cubeToml.NodePool.Master.InternalLb, allYaml.LbPort)
		allYaml.LbIP = cubeToml.NodePool.Master.InternalLb
	}

	//allYaml.ApiSans = cubeToml.Kubernetes.ApiSans

	allYaml.ClusterName = cubeToml.Cube.ClusterName

	allYaml.RegistryInstall = cubeToml.PrivateRegistry.Install
	allYaml.RegistryDataDir = cubeToml.PrivateRegistry.DataDir
	allYaml.Registry = registryIP
	allYaml.RegistryDomain = registryDomain
	allYaml.RegistryPublicCert = isPrivateRegistryPubicCert

	allYaml.Haproxy = cubeToml.NodePool.Master.HaproxyInstall //# Set False When Already Physical Loadbalancer Available"

	allYaml.NfsIP = cubeToml.SharedStorage.StorageIP
	allYaml.StorageInstall = cubeToml.SharedStorage.Install

	allYaml.MasterIsolated = cubeToml.NodePool.Master.Isolated

	//if cubeToml.Cube.StorageClassName != "" {
	//	allYaml.StorageClassName = cubeToml.Cube.StorageClassName
	//} else {
	//	allYaml.StorageClassName = "default-storage"
	//}

	//switch cubeToml.NodePool.Provider.Name {
	//case "aws", "eks":
	//	//todo 확인 필요 && cubeToml.Cube.Provider
	//	if cubeToml.SharedStorage.StorageType == "" {
	//		allYaml.StorageType = "efs"
	//	} else {
	//		allYaml.StorageType = cubeToml.SharedStorage.StorageType
	//	}
	//case "azure", "aks":
	//	//todo 확인필요 && cubeToml.Cube.Provider
	//	if cubeToml.SharedStorage.StorageType == "" {
	//		allYaml.StorageType = "azurefile"
	//	} else {
	//		allYaml.StorageType = cubeToml.SharedStorage.StorageType
	//	}
	//default:
	//	if cubeToml.SharedStorage.StorageType == "" {
	//		allYaml.StorageType = "nfs"
	//	} else {
	//		allYaml.StorageType = cubeToml.SharedStorage.StorageType
	//	}
	//}

	allYaml.LocalRepository = cubeToml.Cube.LocalRepository

	allYaml.AuditLogEnable = cubeToml.Kubernetes.AuditLogEnable

	if cubeToml.Kubernetes.KubeProxyMode == "" {
		allYaml.KubeProxyMode = "iptables"
	} else {
		allYaml.KubeProxyMode = cubeToml.Kubernetes.KubeProxyMode
	}

	if cubeToml.Kubernetes.ContainerRuntime == "" {
		allYaml.ContainerRuntime = "docker"
	} else {
		allYaml.ContainerRuntime = cubeToml.Kubernetes.ContainerRuntime
	}

	if cubeToml.Cube.CertValidityDays > 0 {
		allYaml.CertValidityDays = cubeToml.Cube.CertValidityDays
	} else {
		allYaml.CertValidityDays = 3650
	}
	//vxlan-mode
	allYaml.KubeProxyMode = cubeToml.Kubernetes.KubeProxyMode
	b, _ := yaml.Marshal(allYaml)
	os.MkdirAll(allYamlPath, os.ModePerm)
	ioutil.WriteFile(allYamlPath+"/basic.yml", b, 0600)
}

func CreateExpertYaml(destDir string, cubeToml model.CubeToml) {
	var allYaml = &model.ExpertYaml{}
	Set(allYaml, "default")

	allYamlPath := fmt.Sprintf("%s/group_vars/all", destDir)
	b, _ := yaml.Marshal(allYaml)
	os.MkdirAll(allYamlPath, os.ModePerm)
	ioutil.WriteFile(allYamlPath+"/expert.yml", b, 0600)

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
