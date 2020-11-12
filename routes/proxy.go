package routes

import (
	"github.com/aesirteam/go-srs-sidecar/common"
	"github.com/gin-gonic/gin"
)

type ProxyRouter struct{}

func (a *ProxyRouter) Run(addr string) {
	//Start file watch
	watcher := common.NewWatcher()
	go watcher.MediaFile("./public1")

	engine.Use(func(c *gin.Context) {
		c.Set("proxyHost", "127.0.0.1:8090;remote")
	}, writeHandlerFunc)

	engine.Run(addr)
}

func (a *ProxyRouter) Destory() {

}
