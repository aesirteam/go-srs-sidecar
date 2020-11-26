package routes

import (
	"github.com/aesirteam/go-srs-sidecar/common"
	"github.com/gin-gonic/gin"
	"strings"
)

type ProxyRouter struct{}

func (a *ProxyRouter) Run(addr string) {
	//Start file watch
	watcher := common.NewWatcher()
	go watcher.ConfigFile("anonymous", "")
	go watcher.MediaFile("")

	apiGroup := engine.Group("/api/v1")

	engine.Use(func(c *gin.Context) {
		if strings.HasSuffix(c.Request.URL.Path, ".m3u8") || strings.HasSuffix(c.Request.URL.Path, ".ts") {
			c.Set("proxyHost", watcher.SrsProxyHost+";remote")
		} else {
			c.Abort()
		}
	}, writeHandlerFunc)

	apiGroup.GET("/configmap", writeConfigMapFunc)

	_ = engine.Run(addr)
}
