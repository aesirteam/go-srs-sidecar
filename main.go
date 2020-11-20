package main

import (
	"github.com/aesirteam/go-srs-sidecar/routes"
	"os"
)

func main() {
	var (
		cmd  string
		addr string
		app  routes.App
	)

	switch len(os.Args) {
	case 2:
		cmd, addr = os.Args[1], ":8080"
	case 3:
		cmd, addr = os.Args[1], os.Args[2]
	default:
		cmd, addr = "default", ":8080"
	}
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "webhook":
		app = &routes.WebHookRouter{}
	case "proxy":
		app = &routes.ProxyRouter{}
	default:
		app = &routes.DefaultRouter{}
	}

	app.Run(addr)
}
