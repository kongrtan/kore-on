package cmd_test

import (
	"encoding/base64"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"kore-on/pkg/model"
	"log"
	"net"
	"testing"
	"time"
)

// 패스워드 전달 방식과 타임아웃 전역변수 설정
const (
	CertPassword      = 1
	CertPublicKeyFile = 2
	DefaultTimeout    = 3 // Second
)

// SSH 접속에 필요한 정보를 담는 생성자
type SSH struct {
	IP      string
	User    string
	Cert    string //password or key file path
	Port    int
	session *ssh.Session
	client  *ssh.Client
}

func (S *SSH) readPublicKeyFile(file string) ssh.AuthMethod {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil
	}
	return ssh.PublicKeys(key)
}

// Connect the SSH Server
func (S *SSH) Connect(mode int) {
	var sshConfig *ssh.ClientConfig
	var auth []ssh.AuthMethod
	if mode == CertPassword {
		auth = []ssh.AuthMethod{
			ssh.Password(S.Cert),
		}
	} else if mode == CertPublicKeyFile {
		auth = []ssh.AuthMethod{
			S.readPublicKeyFile(S.Cert),
		}
	} else {
		log.Println("does not support mode: ", mode)
		return
	}

	sshConfig = &ssh.ClientConfig{
		User: S.User,
		Auth: auth,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: time.Second * DefaultTimeout,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", S.IP, S.Port), sshConfig)
	if err != nil {
		fmt.Println(err)
		return
	}

	session, err := client.NewSession()
	if err != nil {
		fmt.Println(err)
		client.Close()
		return
	}

	S.session = session
	S.client = client
}

// RunCmd to SSH Server
func (S *SSH) RunCmd(cmd string) string {
	out, err := S.session.CombinedOutput(cmd)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println(string(out))
	return string(out)
}

func (S *SSH) Close() {
	S.session.Close()
	S.client.Close()
}

func TestCmdOK(t *testing.T) {

	client := &SSH{
		IP:   "192.168.88.161",
		User: "ubuntu",
		Port: 22,
		Cert: "/Users/okpiri/cert/hostacloud/id_rsa",
	}
	client.Connect(CertPublicKeyFile) // If you are using a key file, use 'CertPublicKeyFile' instead.
	aa := client.RunCmd("cat /etc/kubernetes/acloud/acloud-client-kubeconfig")

	//var ab rest.Config ={}

	kubeConfig := flag.String("kubeconfig", "/Users/okpiri/ml88-81/aa", "absolute path to the kubeconfig file")

	//*restclient.Config

	y := model.KubeConfig{}

	err := yaml.Unmarshal([]byte(aa), &y)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	fmt.Printf("%+v\n", y)

	var bb = &restclient.Config{}

	bb.Host = y.Clusters[0].Cluster.Server

	certData, _ := base64.StdEncoding.DecodeString(y.Users[0].User.ClientCertificateData)
	keyData, _ := base64.StdEncoding.DecodeString(y.Users[0].User.ClientKeyData)
	caData, _ := base64.StdEncoding.DecodeString(y.Clusters[0].Cluster.CertificateAuthorityData)

	bb.TLSClientConfig.CertData = certData
	bb.TLSClientConfig.KeyData = keyData
	bb.TLSClientConfig.CAData = caData

	flag.Parse()
	config, err := clientcmd.BuildConfigFromFlags("", *kubeConfig)

	if err != nil {
		fmt.Printf("[ERROR] while build kubernetes client: %s", err.Error())
		return
	}

	fmt.Printf("%+v\n", string(config.TLSClientConfig.CertData))
	//e, err := json.Marshal(&config)
	//if err != nil {
	//	fmt.Println(err)
	//	return
	//}
	//fmt.Println(string(e))

	clientset, err := kubernetes.NewForConfig(bb)
	if err != nil {
		fmt.Printf("[ERROR] while build kubernetes client: %s", err.Error())

	} else {
		fmt.Printf("[ERROR] while build kubernetes client: %f", clientset.CertificatesV1())
	}
	//

	//fmt.Println(aa)
	client.Close()

}
