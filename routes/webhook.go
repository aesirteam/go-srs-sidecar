package routes

import (
	"github.com/aesirteam/go-srs-sidecar/common"
	"github.com/gin-gonic/gin"
	"github.com/json-iterator/go"
	"k8s.io/klog"
	"net/http"
	"path/filepath"
)

type WebHookRouter struct {
	common.RedisPool
	common.S3Client
}

func (a *WebHookRouter) Run(addr string) {
	//Create user admin
	password := a.RedisPool.InitAdminUser()

	//Start file watch
	watcher := common.NewWatcher()
	go watcher.ConfigFile("admin", password)

	//start oss backup
	leaseName := regexpFn.FindString(common.Hostname) + "-leader"
	go common.LeaderElectionRunOrDie(leaseName)

	apiGroup := engine.Group("/api/v1")

	engine.Use(func(c *gin.Context) {
		if ext := filepath.Ext(c.Request.URL.Path); ext == ".m3u8" || ext == ".ts" {
			fs := common.LocalFileSystem{}

			if err := fs.Open(common.Conf.SrsHlsPath + c.Request.URL.Path); err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			defer fs.Close()

			c.Writer.Header().Set("Content-Type", "apication/vnd.apple.mpegurl")
			c.Writer.WriteHeader(http.StatusOK)
			_, _ = fs.WriteTo(c.Writer)

			return
		}
	})

	engine.POST("/auth", func(c *gin.Context) {
		var hook common.WebHookEvent

		if err := c.BindJSON(&hook); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"err": err.Error()})
			return
		}

		if errCode, errMsg := a.RedisPool.TokenAuth(&hook); errCode != http.StatusOK {
			c.AbortWithStatusJSON(errCode, gin.H{"err": errMsg})
			return
		}

		c.AbortWithStatusJSON(http.StatusOK, gin.H{"code": 0})
	})

	engine.POST("/storage", func(c *gin.Context) {
		var hook common.WebHookEvent

		if err := c.BindJSON(&hook); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"err": err.Error()})
			return
		}

		if common.IsLeader {
			if errCode, errMsg := a.RedisPool.TokenAuth(&hook); errCode != http.StatusOK {
				klog.Error(errCode, ": ", errMsg)
			}

			if common.Conf.OssBackupEnabled {
				ch := make(chan error)

				go func() {
					ch <- a.S3Client.FPutObject(hook.Url, common.Conf.SrsHlsPath+"/"+hook.Url)
					//ch <- a.S3Client.FPutObject(hook.M3u8Url, common.Conf.SrsHlsPath + "/" + hook.M3u8Url)
				}()

				select {
				case err := <-ch:
					close(ch)
					if err != nil {
						klog.Error(err)
					}
				}
			}
		}

		c.AbortWithStatusJSON(http.StatusOK, gin.H{"code": 0})
	})

	apiGroup.POST("/clusters", func(c *gin.Context) {
		key := common.STREAM_PREFIX + c.DefaultQuery("vhost", common.DEFAULT_VHOST) + "/" + c.Query("app") + "/" + c.Query("stream")

		if info, err := a.RedisPool.GetStreamInfo(key); err == nil {
			if body := jsoniter.Get(info.Meta.ClusterOrigin); body.LastError() == nil {
				c.AbortWithStatusJSON(http.StatusOK, gin.H{"code": 0, "data": body.GetInterface()})
				return
			}
		}

		c.AbortWithStatus(http.StatusInternalServerError)
	})

	apiGroup.GET("/configmap", func(c *gin.Context) {
		fs := common.LocalFileSystem{}

		if err := fs.Open(common.Conf.SrsCfgFile); err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		defer fs.Close()

		c.Writer.Header().Set("Content-Type", "application/octet-stream")
		c.Writer.WriteHeader(http.StatusOK)
		_, _ = fs.WriteTo(c.Writer)
	})

	defer a.RedisPool.Close()

	_ = engine.Run(addr)
}
