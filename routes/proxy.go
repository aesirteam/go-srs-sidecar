package routes

import (
	"github.com/aesirteam/go-srs-sidecar/common"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

type ProxyRouter struct{}

func (a *ProxyRouter) Run(addr string) {
	//Start file watch
	watcher := common.NewWatcher()
	go watcher.ConfigFile("Basic YW5vbnltb3VzOg==") //anonymous

	go watcher.MediaFile("")

	engine.Use(func(c *gin.Context) {
		if strings.HasSuffix(c.Request.URL.Path, ".m3u8") || strings.HasSuffix(c.Request.URL.Path, ".ts") {
			c.Set("proxyHost", watcher.SrsProxyHost+";remote")
		} else {
			c.Abort()
		}
	}, writeHandlerFunc)

	engine.GET("/api/v1/configmap", func(c *gin.Context) {
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

func (a *ProxyRouter) Destory() {

}
