package main

import (
	"flag"
	"github.com/aesirteam/go-srs-sidecar/common"
	"github.com/aesirteam/go-srs-sidecar/routes"
	"strconv"
)

func main() {

	var (
		mode string
		port int
		app  routes.App
	)

	flag.StringVar(&mode, "mode", "edge", "run mode")
	flag.IntVar(&port, "port", 8080, "listen port")
	flag.BoolVar(&common.LeaderElection, "leader-election", false, "leader-election with pods")

	flag.StringVar(&common.Conf.SrsProxyHost, "srs-proxy-server", "127.0.0.1:8080", "")
	flag.StringVar(&common.Conf.SrsApiServer, "srs-api-server", "127.0.0.1:1985", "")
	flag.StringVar(&common.Conf.SrsCfgFile, "srs-cfg-file", "./conf/srs.conf", "")
	flag.StringVar(&common.Conf.SrsHlsPath, "srs-hls-path", "./public", "")
	flag.Int64Var(&common.Conf.SrsHlsExpire, "srs-hls-expire", 180, "")

	flag.Int64Var(&common.Conf.DefaultTokenExpire, "auth-token-expire", 60, "")

	flag.Parse()

	switch mode {
	case "origin":
		app = &routes.WebHookRouter{}
	case "edge":
		app = &routes.DefaultRouter{}
	case "proxy":
		app = &routes.ProxyRouter{}
	}

	app.Run(":" + strconv.Itoa(port))

}
