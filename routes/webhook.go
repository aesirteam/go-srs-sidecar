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
	if common.LeaderElection {
		leaseName := regexpFn.FindString(common.Hostname) + "-leader"
		go common.LeaderElectionRunOrDie(leaseName)
	}

	apiGroup := engine.Group("/api/v1")
	userGroup := engine.Group("/", basicAuth(false, &a.RedisPool))

	engine.Use(func(c *gin.Context) {
		if ext := filepath.Ext(c.Request.URL.Path); ext == ".m3u8" || ext == ".ts" {
			fs := common.LocalFileSystem{Path: common.Conf.SrsHlsPath + c.Request.URL.Path}

			if _, err := fs.Open(); err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			defer fs.Close()

			//c.Writer.Header().Set("Content-Type", "apication/vnd.apple.mpegurl")
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

		if errCode, errMsg, _ := a.RedisPool.TokenAuth(&hook); errCode != http.StatusOK {
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
			if errCode, errMsg, streamInfo := a.RedisPool.TokenAuth(&hook); errCode != http.StatusOK {
				klog.Error(errCode, ": ", errMsg)
			} else if streamInfo.Meta.HlsBackup {
				ch := make(chan error, 1)
				defer close(ch)

				go func() {
					ch <- a.S3Client.FPutObject(hook.Url, common.Conf.SrsHlsPath+"/"+hook.Url)
					//ch <- a.S3Client.FPutObject(hook.M3u8Url, common.Conf.SrsHlsPath + "/" + hook.M3u8Url)
				}()

				if err := <-ch; err != nil {
					klog.Error(err)
				}
			}

			goto done
		}

		if errCode, errMsg, _ := a.RedisPool.TokenAuth(&hook); errCode != http.StatusOK {
			klog.Error(errCode, ": ", errMsg)
		}

	done:
		c.AbortWithStatusJSON(http.StatusOK, gin.H{"code": 0})
	})

	userGroup.GET("/user/token", echoUserTokenFunc)

	apiGroup.GET("/configmap", writeConfigMapFunc)

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

	defer a.RedisPool.Close()

	_ = engine.Run(addr)
}
