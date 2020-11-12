package common

import "sync"

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

	once sync.Once
}

const (
	LETTER_BYTES  = "abcdefghijklmnopqrstuvwxyz0123456789"
	PASSWD_BYTES  = "aAbBcCdDeEfFgGhHiIjJkKlLmMnNpPqQrRsStTuUvVwWxXyYzZ123456789"
	STREAM_PREFIX = "stream:"
	DEFAULT_VHOST = "__defaultVhost__"
)
