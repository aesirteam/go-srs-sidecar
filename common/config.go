package common

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"github.com/caarlos0/env/v6"
	"io"
	"k8s.io/klog"
	"os"
	"os/exec"
	"strings"
)

const (
	STREAM_PREFIX = "stream:"
	DEFAULT_VHOST = "__defaultVhost__"
)

var (
	Conf CustomConfig

	PodIp          string
	Hostname       string
	Namespace      string
	LeaderElection bool
	IsLeader       bool
	encoding       = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567")
)

func init() {
	done := make(chan bool)
	defer close(done)

	go func() {
		var err error

		if err = env.Parse(&Conf); err != nil {
			klog.Fatal(err)
		}

		if Hostname, err = os.Hostname(); err != nil {
			klog.Fatal(err)
		}

		if PodIp, err = execCommand("hostname", "-i"); err != nil {
			klog.Fatal(err)
		}

		if Namespace, err = execCommand("cat", "/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err != nil {
			klog.Warning(err)
		}

		done <- true
	}()

	select {
	case <-done:
		//klog.Info("PodIp: ", PodIp)
		//klog.Info("Hostname: ", Hostname)
		//klog.Info("Namespace: ", Namespace)
	}
}

func randString(len int) string {
	buff := make([]byte, len)
	if _, err := io.ReadFull(rand.Reader, buff); err != nil {
		klog.Fatal(err)
	}

	str := string(buff[0]%26+'a') + strings.TrimRight(encoding.EncodeToString(buff[1:]), "=")
	return str[:len]
}

func execCommand(name string, arg ...string) (string, error) {
	cmd := exec.Command(name, arg...)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}

	return strings.TrimSpace(out.String()), nil
}

func genHeaderAuthorization(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

func encodeUserToken(user, password string) string {
	nonce := randString(8)
	h := md5.New()
	h.Write([]byte(user + ":" + password + "@" + nonce))
	return hex.EncodeToString(h.Sum(nil)) + nonce
}

func ParseHeaderAuthorization(val string) (user string, password string) {
	if len(val) > 0 {
		if authorization := strings.Split(val, " "); len(authorization) > 1 {
			if bs, err := base64.StdEncoding.DecodeString(authorization[1]); err == nil {
				auth := strings.Split(string(bs), ":")
				user, password = auth[0], auth[1]
			}
		}
	}

	return
}

type CustomConfig struct {
	RedisMode      string `env:"redis_mode" envDefault:"Standalone"`
	RedislHost     string `env:"redis_host" envDefault:"127.0.0.1"`
	RedisPort      int    `env:"redis_port" envDefault:"6379"`
	RedisMaster    string `env:"redis_master" envDefault:"mymaster"`
	RedisPassword  string `env:"redis_pass"`
	RedisDatabase  int    `env:"redis_database"`
	RedisMaxIdle   int    `env:"redis_pool_min" envDefault:"3"`
	RedisMaxActive int    `env:"redis_pool_max" envDefault:"10"`

	Endpoint        string `env:"minio_endpoint" envDefault:"play.min.io"`
	Port            int    `env:"minio_port" envDefault:"80"`
	AccessKeyID     string `env:"minio_accessKey"`
	SecretAccessKey string `env:"minio_secretKey"`
	UseSSL          bool   `env:"minio_use_ssl" envDefault:"false"`
	BucketName      string `env:"minio_bucketName"`
	BucketPrefix    string `env:"minio_bucketPrefix"`

	DefaultAdminPasswd string `env:"DEFAULT_ADMIN_PASSWORD"`

	SrsApiServer string
	SrsCfgFile   string
	SrsHlsPath   string
	SrsProxyHost string
	SrsHlsExpire int64

	DefaultTokenExpire int64
}
