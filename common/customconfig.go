package common

import (
	"bytes"
	"github.com/caarlos0/env/v6"
	"github.com/sirupsen/logrus"
	"os"
	"os/exec"
)

const (
	LETTER_BYTES  = "abcdefghijklmnopqrstuvwxyz0123456789"
	PASSWD_BYTES  = "aAbBcCdDeEfFgGhHiIjJkKlLmMnNpPqQrRsStTuUvVwWxXyYzZ123456789"
	STREAM_PREFIX = "stream:"
	DEFAULT_VHOST = "__defaultVhost__"
)

var (
	HostName string
	PodIp    string
	Conf     = CustomConfig{}
	Logger   = logrus.Logger{
		Out:          os.Stdout,
		Formatter:    &logrus.TextFormatter{FullTimestamp: true},
		Level:        logrus.InfoLevel,
		ExitFunc:     os.Exit,
		ReportCaller: false,
	}
)

func init() {
	if err := env.Parse(&Conf); err != nil {
		Logger.Fatal(err)
	}

	ch := make(chan string, 1)
	defer close(ch)

	go execCommand(ch, "hostname", "-f")
	go execCommand(ch, "hostname", "-i")

	HostName = <-ch
	PodIp = <-ch

}

func execCommand(ch chan string, name string, arg ...string) {
	cmd := exec.Command(name, arg...)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		ch <- out.String()[:out.Len()-1]
		return
	}

	ch <- ""
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

	DefaultAdminPasswd string `env:"DEFAULT_ADMIN_PASSWORD"`
	DefaultTokenExpire int64  `env:"DEFAULT_TOKEN_EXPIRE" envDefault:"60"`

	SrsApiServer string `env:"SRS_API_SERVER" envDefault:"127.0.0.1:1985"`
	SrsCfgFile   string `env:"SRS_CONF_FILE" envDefault:"./conf/srs.conf"`
	SrsHlsPath   string `env:"SRS_HLS_PATH" envDefault:"./public"`
	SrsHlsExpire int64  `env:"SRS_HLS_EXPIRE" envDefault:"60"`
	SrsProxyHost string `env:"SRS_PROXY_HOST" envDefault:"127.0.0.1:8080"`
}
