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

func (a *DefaultRouter) basicAuth(isAdmin bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user, password string

		authorization := strings.Split(c.GetHeader("Authorization"), " ")
		if len(authorization) < 2 {
			goto Unauthorized
		}

		user, password = parseHeaderAuthorization(authorization[1])
		if len(password) == 0 {
			goto Unauthorized
		}

		if isAdmin && user != "admin" {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		if info, err := a.RedisPool.GetUserInfo(user); err == nil && password == info.Password {
			if a.RedisPool.CheckTokenExpire(info) {
				info.Token = common.EncodeUserToken(user, password, "")
				_ = a.RedisPool.RefreshToken(info, 0)
			}

			c.Set(gin.AuthUserKey, user)

			return
		}

	Unauthorized:
		c.Header("WWW-Authenticate", "Authorization Required")
		c.AbortWithStatus(http.StatusUnauthorized)
	}
}

func (a *DefaultRouter) Run(addr string) {
	//Create user admin
	password := a.RedisPool.InitAdminUser()

	//Start file watch
	watcher := common.NewWatcher()
	go watcher.ConfigFile(
		genHeaderAuthorization("admin", password),
	)

	go watcher.MediaFile("")

	api := engine.Group("/api/v1", a.basicAuth(true))
	user := engine.Group("/", a.basicAuth(false))

	engine.Use(func(c *gin.Context) {
		if ext := filepath.Ext(c.Request.URL.Path); ext == ".m3u8" || ext == ".ts" {
			app, stream := filepath.Split(c.Request.URL.Path)
			if errCode, err, originIp := a.RedisPool.TokenAuth(&common.WebHookEvent{
				Action: "on_play",
				Vhost:  c.DefaultQuery("vhost", common.DEFAULT_VHOST),
				App:    filepath.Base(app),
				Stream: regexpFn.FindString(stream),
				Param:  c.Request.URL.RawQuery,
			}); errCode != http.StatusOK {
				if errCode == http.StatusUnauthorized {
					c.Header("WWW-Authenticate", `Basic realm="Authorization Required"`)
				}
				c.String(errCode, "%s\n", err.Error())
				c.Abort()
			} else {
				c.Set("proxyHost", originIp+":8080")
			}
		}
	}, writeHandlerFunc)

	user.GET("/user/token", func(c *gin.Context) {
		user := c.GetString(gin.AuthUserKey)

		if info, err := a.RedisPool.GetUserInfo(user); err == nil {
			//c.PureJSON(http.StatusOK, gin.H{
			//	"account":	user,
			//	"param":	"?u=" + user + "&t=" + info.Token,
			//	"expire":	info.TokenExpire,
			//	"token":	info.Token[:32],
			//	"nonce":	info.Token[32:],
			//})
			c.String(http.StatusOK, "?u=%s&t=%s", user, info.Token)
		} else {
			c.String(http.StatusInternalServerError, "%s", err.Error())
		}
	})

	user.POST("/user/change_pwd", func(c *gin.Context) {
		//
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

	api.POST("/users", func(c *gin.Context) {
		var postData struct {
			Users []string `json:"filter"`
		}

		var (
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

	api.POST("/user/:account", func(c *gin.Context) {
		var postData struct {
			Password string `json:"password"`
		}

		var (
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

			if err = a.RedisPool.AddUser(info); err != nil {
				goto ServerError
			}

			if info, err = a.RedisPool.GetUserInfo(info.Account); err != nil {
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

	api.DELETE("/user/:account", func(c *gin.Context) {
		if err := a.RedisPool.DeleteUser(c.Param("account")); err == nil {
			c.AbortWithStatusJSON(http.StatusOK, gin.H{"code": 0})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"err": err.Error()})
		}
	})

	api.POST("/streams", func(c *gin.Context) {
		var postData struct {
			Streams []string `json:"filter"`
		}

		var (
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

	api.POST("/stream/:app/:stream", func(c *gin.Context) {
		var postData struct {
			Owner    string            `json:"owner"`
			Metadata common.StreamMeta `json:"metadata"`
			Users    []string          `json:"users"`
		}

		var (
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

	api.DELETE("/stream/:app/:stream", func(c *gin.Context) {
		var postData struct {
			Users []string `json:"users"`
		}

		var (
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

	_ = engine.Run(addr)
}

func (a *DefaultRouter) Destory() {
	a.RedisPool.Close()
}
