package common

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"github.com/caarlos0/env/v6"
	"k8s.io/klog"
	"math/rand"
	"os"
	"os/exec"
	"strings"
)

const (
	LETTER_BYTES  = "abcdefghijklmnopqrstuvwxyz0123456789"
	PASSWD_BYTES  = "aAbBcCdDeEfFgGhHiIjJkKlLmMnNpPqQrRsStTuUvVwWxXyYzZ123456789"
	STREAM_PREFIX = "stream:"
	DEFAULT_VHOST = "__defaultVhost__"
)

var (
	Conf CustomConfig

	PodIp     string
	Hostname  string
	Namespace string
	IsLeader  bool
)

func init() {
	if err := env.Parse(&Conf); err != nil {
		klog.Fatal(err)
		os.Exit(0)
	}

	ch := make(chan string, 3)
	go func() {
		ch <- execCommand("hostname")
		ch <- execCommand("hostname", "-i")
		ch <- execCommand("cat", "/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	}()

	select {
	case Hostname = <-ch:
		PodIp = <-ch
		Namespace = <-ch
		close(ch)
	}

	//klog.Info(PodIp, " ", Hostname, " ", Namespace)
}

func execCommand(name string, arg ...string) (result string) {
	cmd := exec.Command(name, arg...)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		result = strings.TrimSpace(out.String())
	}

	return
}

func genHeaderAuthorization(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

func genUserPassword(password string) string {
	if len(password) == 0 {
		b := make([]byte, 16)
		for i := range b {
			b[i] = PASSWD_BYTES[rand.Intn(len(PASSWD_BYTES))]
		}
		return string(b)
	}

	return password
}

func encodeUserToken(user, password string) string {
	nonce := func() string {
		b := make([]byte, 8)
		for i := range b {
			b[i] = LETTER_BYTES[rand.Intn(len(LETTER_BYTES))]
		}
		return string(b)
	}()

	h := md5.New()
	h.Write([]byte(user + ":" + password + "@" + nonce))
	return hex.EncodeToString(h.Sum(nil)) + nonce
}

func ParseHeaderAuthorization(authEnc string) (string, string) {
	if len(authEnc) == 0 {
		return "", ""
	}
	_bytes, _ := base64.StdEncoding.DecodeString(authEnc)
	val := strings.Split(string(_bytes), ":")
	return val[0], val[1]
}

type CustomConfig struct {
	SentinelHost string `env:"redis_sentinel_host" envDefault:"127.0.0.1"`
	SentinelPort int    `env:"redis_sentinel_port" envDefault:"26379"`
	MasterName   string `env:"redis_name" envDefault:"mymaster"`
	Password     string `env:"redis_pass"`
	Database     int    `env:"redis_database"`
	MaxIdle      int    `env:"redis_pool_min" envDefault:"3"`
	MaxActive    int    `env:"redis_pool_max" envDefault:"10"`

	Endpoint        string `env:"minio_endpoint" envDefault:"play.min.io"`
	Port            int    `env:"minio_port" envDefault:"80"`
	AccessKeyID     string `env:"minio_accessKey"`
	SecretAccessKey string `env:"minio_secretKey"`
	UseSSL          bool   `env:"minio_use_ssl" envDefault:"false"`
	BucketName      string `env:"minio_bucketName"`
	BucketPrefix    string `env:"minio_bucketPrefix"`

	SrsApiServer string `env:"SRS_API_SERVER" envDefault:"127.0.0.1:1985"`
	SrsCfgFile   string `env:"SRS_CONF_FILE" envDefault:"./conf/srs.conf"`
	SrsHlsPath   string `env:"SRS_HLS_PATH" envDefault:"./public"`
	SrsHlsExpire int64  `env:"SRS_HLS_EXPIRE" envDefault:"60"`
	SrsProxyHost string `env:"SRS_PROXY_HOST" envDefault:"127.0.0.1:8080"`

	DefaultAdminPasswd string `env:"DEFAULT_ADMIN_PASSWORD"`
	DefaultTokenExpire int64  `env:"DEFAULT_TOKEN_EXPIRE" envDefault:"60"`
	OssBackupEnabled   bool   `env:"OSS_BACKUP_ENABLED"`
}
