module github.com/aesirteam/go-srs-sidecar

go 1.13

require (
	github.com/FZambia/sentinel v1.1.0
	github.com/caarlos0/env/v6 v6.4.0
	github.com/fsnotify/fsnotify v1.4.9
	github.com/gin-gonic/gin v1.6.3
	github.com/gomodule/redigo v2.0.0+incompatible
	github.com/json-iterator/go v1.1.10
	github.com/minio/minio-go/v7 v7.0.5
	github.com/sirupsen/logrus v1.7.0
)

replace github.com/fsnotify/fsnotify v1.4.9 => github.com/aesirteam/fsnotify v1.4.10-0.20201112082952-aed89c233210
