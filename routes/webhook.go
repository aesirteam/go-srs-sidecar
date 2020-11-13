package routes

import (
	"github.com/aesirteam/go-srs-sidecar/common"
	"github.com/gin-gonic/gin"
	"github.com/json-iterator/go"
	"net/http"
	"path/filepath"
)

type WebHookRouter struct {
	common.RedisPool
}

func (a *WebHookRouter) Run(addr string) {
	//Create user admin
	password := a.RedisPool.InitAdminUser()

	//Start file watch
	watcher := common.NewWatcher()
	go watcher.ConfigFile(
		genHeaderAuthorization("admin", password),
	)

	api := engine.Group("/api/v1")

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

		if errCode, err, _ := a.RedisPool.TokenAuth(&hook); err != nil {
			c.AbortWithStatusJSON(errCode, gin.H{"err": err.Error()})
			return
		}

		c.AbortWithStatusJSON(http.StatusOK, gin.H{"code": 0})
	})

	//engine.POST("/storage", func (c *gin.Context) {
	//	var data struct {
	//		Url			string	`json:"url" binding:"required"`
	//		M3u8Url		string	`json:"m3u8_url" binding:"required"`
	//	}
	//
	//	ch := make(chan int)
	//	//defer close(ch)
	//
	//	if c.BindJSON(&data) == nil {
	//		go a.S3Client.FPutObject(ch, data.Url, DEFAULT_STATIC + "/" + data.Url)
	//		go a.S3Client.FPutObject(ch, data.M3u8Url, DEFAULT_STATIC + "/" + data.M3u8Url)
	//
	//		if (<-ch + <-ch) == 0 {
	//			c.AbortWithStatusJSON(http.StatusOK, gin.H{"code": 0})
	//			return
	//		}
	//	}
	//
	//	c.AbortWithStatus(http.StatusInternalServerError)
	//})

	api.POST("/clusters", func(c *gin.Context) {
		key := common.STREAM_PREFIX + c.DefaultQuery("vhost", common.DEFAULT_VHOST) + "/" + c.Query("app") + "/" + c.Query("stream")

		if info, err := a.RedisPool.GetStreamInfo(key); err == nil {
			if body := jsoniter.Get(info.Meta.ClusterOrigin); body.LastError() == nil {
				c.AbortWithStatusJSON(http.StatusOK, gin.H{"code": 0, "data": body.GetInterface()})
				return
			}
		}

		c.AbortWithStatus(http.StatusInternalServerError)
	})

	api.GET("/configmap", func(c *gin.Context) {
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

	_ = engine.Run(addr)
}

func (a *WebHookRouter) Destory() {
	a.RedisPool.Close()
}
