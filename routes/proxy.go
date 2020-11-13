package routes

import (
	"github.com/aesirteam/go-srs-sidecar/common"
	"github.com/gin-gonic/gin"
)

type ProxyRouter struct{}

func (a *ProxyRouter) Run(addr string) {
	//Start file watch
	watcher := common.NewWatcher()
	go watcher.MediaFile("")

	engine.Use(func(c *gin.Context) {
		c.Set("proxyHost", watcher.SrsProxyHost+";remote")
	}, writeHandlerFunc)

	_ = engine.Run(addr)
}

func (a *ProxyRouter) Destory() {

}
