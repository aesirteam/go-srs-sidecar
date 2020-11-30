package routes

import (
	"github.com/aesirteam/go-srs-sidecar/common"
	"github.com/gin-gonic/gin"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	engine    = gin.New()
	regexpTs  = regexp.MustCompile(`.ts`)
	regexpFn  = regexp.MustCompile(`^(\w+)`)
	transport = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		//MaxIdleConns:        	0,
		//MaxConnsPerHost:		0,
		MaxIdleConnsPerHost: 512,
		IdleConnTimeout:     30 * time.Second,
	}
)

type App interface {
	Run(addr string)
}

func basicAuth(isAdmin bool, redisPool *common.RedisPool) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, password := common.ParseHeaderAuthorization(c.GetHeader("Authorization"))
		if len(user) == 0 || len(password) == 0 {
			c.Header("WWW-Authenticate", "Authorization Required")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if isAdmin && user != "admin" {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		uc := make(chan func() (*common.UserInfo, error), 1)
		defer close(uc)

		go func() {
			uc <- func() (*common.UserInfo, error) { return redisPool.GetUserInfo(user) }
		}()

		if info, err := (<-uc)(); err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
		} else {
			if password != info.Password {
				c.Header("WWW-Authenticate", "Authorization Required")
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			if info, err = redisPool.RefreshToken(info); err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			c.Set(gin.AuthUserKey, info)
		}
	}
}

func writeHandlerFunc(c *gin.Context) {
	transformFile := func(fs common.FileSystem) {
		path, err := fs.Open()
		if err != nil {
			if statusCode, err := strconv.Atoi(err.Error()); err == nil {
				c.AbortWithStatus(statusCode)
			}
			return
		}
		defer fs.Close()

		var (
			readLen int
			buf     = make([]byte, 4096)
		)

		for {
			if readLen, err = fs.Read(buf); err != nil && err != io.EOF {
				return
			}

			if readLen == 0 {
				break
			}

			c.Writer.WriteHeader(http.StatusOK)

			if strings.HasSuffix(path, ".m3u8") {
				c.Writer.Header().Set("Content-Type", "apication/vnd.apple.mpegurl")
				if c.Request.Header.Get("proxyMode") == "remote" {
					_, err = c.Writer.Write(buf[:readLen])
				} else {
					_, err = c.Writer.Write(regexpTs.ReplaceAll(buf[:readLen], []byte(".ts?"+c.Request.URL.RawQuery)))
				}
			} else if strings.HasSuffix(path, ".ts") {
				c.Writer.Header().Set("Content-Type", "video/MP2T")
				_, err = c.Writer.Write(buf[:readLen])
				if t, ok := fs.(*common.HttpFileSystem); ok {
					_, err = t.Write(buf[:readLen])
				}
			}

			c.Writer.(http.Flusher).Flush()
		}

		return
	}

	c.Request.URL.Scheme = "http"
	c.Request.URL.Host = func(host string) string {
		if idx := strings.Index(host, ";"); idx == -1 {
			c.Request.Header.Set("proxyMode", "")
			return host
		} else {
			c.Request.Host = host[:idx]
			c.Request.Header.Set("proxyMode", host[idx+1:])
			return c.Request.Host
		}
	}(c.GetString("proxyHost"))

	path := common.Conf.SrsHlsPath + c.Request.URL.Path

	if _, err := os.Stat(path); os.IsNotExist(err) {
		transformFile(&common.HttpFileSystem{Path: path, Client: func() (*http.Response, error) {
			return transport.RoundTrip(c.Request)
		}})
	} else {
		if c.Request.Header.Get("proxyMode") == "remote" {

			ch := make(chan func() (int, error), 1)
			defer close(ch)

			go func() {
				ch <- func() (int, error) {
					c.Request.URL.Path = "/verify" + c.Request.URL.Path
					resp, err := transport.RoundTrip(c.Request)
					if err != nil || resp == nil {
						return 500, err
					}
					defer resp.Body.Close()

					return resp.StatusCode, err
				}
			}()

			if statusCode, err := (<-ch)(); err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			} else if statusCode != http.StatusOK {
				c.AbortWithStatus(statusCode)
				return
			}
		}

		transformFile(&common.LocalFileSystem{Path: path})
	}
}

func writeConfigMapFunc(c *gin.Context) {
	fs := common.LocalFileSystem{Path: common.Conf.SrsCfgFile}

	if _, err := fs.Open(); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	defer fs.Close()

	///c.Writer.Header().Set("Content-Type", "application/octet-stream")
	c.Writer.WriteHeader(http.StatusOK)
	_, _ = fs.WriteTo(c.Writer)
}

func echoUserTokenFunc(c *gin.Context) {
	info := c.MustGet(gin.AuthUserKey).(*common.UserInfo)
	c.String(http.StatusOK, "?u=%s&t=%s", info.Account, info.Token)
}
