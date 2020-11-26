package routes

import (
	"errors"
	"github.com/aesirteam/go-srs-sidecar/common"
	"github.com/gin-gonic/gin"
	"net/http"
	"path/filepath"
	"strings"
)

type DefaultRouter struct {
	common.RedisPool
}

func (a *DefaultRouter) Run(addr string) {
	//Create user admin
	password := a.RedisPool.InitAdminUser()

	//Start file watch
	watcher := common.NewWatcher()
	go watcher.ConfigFile("admin", password)
	go watcher.MediaFile("")

	apiGroup := engine.Group("/api/v1", basicAuth(true, &a.RedisPool))
	userGroup := engine.Group("/", basicAuth(false, &a.RedisPool))

	engine.GET("/verify/:app/:stream", func(c *gin.Context) {
		errCode, _ := a.RedisPool.TokenAuth(&common.WebHookEvent{
			Action: "on_play",
			Vhost:  c.DefaultQuery("vhost", common.DEFAULT_VHOST),
			App:    c.Param("app"),
			Stream: regexpFn.FindString(c.Param("stream")),
			Param:  c.Request.URL.RawQuery,
		})

		c.AbortWithStatus(errCode)
	})

	engine.Use(func(c *gin.Context) {
		if strings.HasSuffix(c.Request.URL.Path, ".m3u8") || strings.HasSuffix(c.Request.URL.Path, ".ts") {
			app, stream := filepath.Split(c.Request.URL.Path)
			if errCode, errMsg := a.RedisPool.TokenAuth(&common.WebHookEvent{
				Action: "on_play",
				Vhost:  c.DefaultQuery("vhost", common.DEFAULT_VHOST),
				App:    filepath.Base(app),
				Stream: regexpFn.FindString(stream),
				Param:  c.Request.URL.RawQuery,
			}); errCode != http.StatusOK {
				if errCode == http.StatusUnauthorized {
					c.Header("WWW-Authenticate", `Basic realm="Authorization Required"`)
				}
				c.String(errCode, "%s\n", errMsg)
				c.Abort()
				return
			}

			c.Set("proxyHost", common.Conf.SrsProxyHost)
		} else {
			c.Abort()
		}
	}, writeHandlerFunc)

	userGroup.GET("/user/token", echoUserTokenFunc)

	apiGroup.GET("/configmap", writeConfigMapFunc)

	apiGroup.POST("/users", func(c *gin.Context) {
		var (
			postData struct {
				Users []string `json:"filter"`
			}
			err    error
			result []common.UserInfo
		)
		if err = c.BindJSON(&postData); err != nil {
			goto ServerError
		}

		if result, err = a.RedisPool.GetUsers(postData.Users); err == nil {
			c.AbortWithStatusJSON(http.StatusOK, result)
			return
		}

	ServerError:
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"err": err.Error()})
	})

	apiGroup.POST("/user/:account", func(c *gin.Context) {
		var (
			postData struct {
				Password string `json:"password"`
			}
			err  error
			info *common.UserInfo
			cmd  = c.DefaultQuery("cmd", "new")
		)

		if err = c.BindJSON(&postData); err != nil {
			goto ServerError
		}

		switch cmd {
		case "new":
			info = &common.UserInfo{
				Account:  c.Param("account"),
				Password: postData.Password,
			}

			if info, err = a.RedisPool.AddUser(info); err != nil {
				goto ServerError
			}

			c.AbortWithStatusJSON(http.StatusOK, gin.H{
				"account":  info.Account,
				"password": info.Password,
				"token":    info.Token,
			})
			return

		case "change_pwd":
			return
		default:
			err = errors.New("CMD only support new/change_pwd")
		}

	ServerError:
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"err": err.Error()})
	})

	apiGroup.DELETE("/user/:account", func(c *gin.Context) {
		if err := a.RedisPool.DeleteUser(c.Param("account")); err == nil {
			c.AbortWithStatusJSON(http.StatusOK, gin.H{"code": 0})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"err": err.Error()})
		}
	})

	apiGroup.POST("/streams", func(c *gin.Context) {
		var (
			postData struct {
				Streams []string `json:"filter"`
			}
			err    error
			result []common.StreamInfo
		)

		if err = c.BindJSON(&postData); err != nil {
			goto ServerError
		}

		for i := 0; i < len(postData.Streams); i++ {
			if strings.Index(postData.Streams[i], common.STREAM_PREFIX) == -1 {
				postData.Streams[i] = common.STREAM_PREFIX + postData.Streams[i]
			}
		}

		if result, err = a.RedisPool.GetStreams(postData.Streams); err == nil {
			c.AbortWithStatusJSON(http.StatusOK, result)
			return
		}

	ServerError:
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"err": err.Error()})
	})

	apiGroup.POST("/stream/:app/:stream", func(c *gin.Context) {
		var (
			postData struct {
				Owner    string            `json:"owner"`
				Metadata common.StreamMeta `json:"metadata"`
				Users    []string          `json:"users"`
			}
			err    error
			stream *common.StreamInfo
			key    = common.STREAM_PREFIX + c.DefaultQuery("vhost", common.DEFAULT_VHOST) + "/" + c.Param("app") + "/" + c.Param("stream")
			cmd    = c.DefaultQuery("cmd", "new")
		)

		if err = c.BindJSON(&postData); err != nil {
			goto ServerError
		}

		switch cmd {
		case "new":
			if stream, err = a.RedisPool.NewStream(key, postData.Owner); err == nil {
				c.AbortWithStatusJSON(http.StatusOK, stream)
				return
			}
		case "subscribe":
			if stream, err = a.RedisPool.SubscribeStream(key, postData.Users); err == nil {
				c.AbortWithStatusJSON(http.StatusOK, stream)
				return
			}
		case "update":
			if stream, err = a.RedisPool.UpdateStreamMetadata(key, postData.Metadata); err == nil {
				c.AbortWithStatusJSON(http.StatusOK, stream)
				return
			}
		default:
			err = errors.New("CMD only support new/update/subscribe")
		}

	ServerError:
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"err": err.Error()})
	})

	apiGroup.DELETE("/stream/:app/:stream", func(c *gin.Context) {
		var (
			postData struct {
				Users []string `json:"users"`
			}
			err    error
			stream *common.StreamInfo
			key    = common.STREAM_PREFIX + c.DefaultQuery("vhost", common.DEFAULT_VHOST) + "/" + c.Param("app") + "/" + c.Param("stream")
			cmd    = c.DefaultQuery("cmd", "new")
		)

		if err = c.BindJSON(&postData); err != nil {
			goto ServerError
		}

		switch cmd {
		case "unsubscribe":
			if stream, err = a.RedisPool.UnsubscribeStream(key, postData.Users); err == nil {
				c.AbortWithStatusJSON(http.StatusOK, stream)
				return
			}
		case "force":
			if err = a.RedisPool.DeleteStream(key); err == nil {
				c.JSON(http.StatusOK, gin.H{"code": 0})
				return
			}
		default:
			err = errors.New("CMD only support unsubscribe/force")
		}

	ServerError:
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"err": err.Error()})
	})

	defer a.RedisPool.Close()

	_ = engine.Run(addr)
}
