module github.com/aesirteam/go-srs-sidecar

go 1.13

require (
	github.com/FZambia/sentinel v1.1.0
	github.com/caarlos0/env/v6 v6.4.0
	github.com/fsnotify/fsnotify v1.4.9
	github.com/gin-gonic/gin v1.6.3
	github.com/gomodule/redigo v2.0.0+incompatible
	github.com/google/uuid v1.1.1
	github.com/json-iterator/go v1.1.10
	github.com/minio/minio-go/v7 v7.0.5
	k8s.io/apimachinery v0.19.4
	k8s.io/client-go v0.0.0-00010101000000-000000000000
	k8s.io/klog v1.0.0
)

replace (
	github.com/fsnotify/fsnotify => github.com/aesirteam/fsnotify v1.4.10-0.20201112082952-aed89c233210
	github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.1.0
	k8s.io/client-go => github.com/kubernetes/client-go v0.0.0-20201028152158-ffaa1909813a
)
