package routes

import (
	"encoding/base64"
	"github.com/aesirteam/go-srs-sidecar/common"
	"github.com/gin-gonic/gin"
	jsoniter "github.com/json-iterator/go"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var (
	engine   = gin.New()
	regexpTs = regexp.MustCompile(`.ts`)
	regexpFn = regexp.MustCompile(`^(\w+)`)
	json     = jsoniter.ConfigCompatibleWithStandardLibrary
)

type App interface {
	Run(addr string)
	Destory()
}

func genHeaderAuthorization(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

func parseHeaderAuthorization(authEnc string) (string, string) {
	if len(authEnc) == 0 {
		return "", ""
	}
	_bytes, _ := base64.StdEncoding.DecodeString(authEnc)
	val := strings.Split(string(_bytes), ":")
	return val[0], val[1]
}

func writeHandlerFunc(c *gin.Context) {
	transformFile := func(path string, fs common.FileSystem) (err error) {
		if err = fs.Open(path); err != nil {
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

			c.Writer.Header().Set("Content-Type", "apication/vnd.apple.mpegurl")
			c.Writer.WriteHeader(http.StatusOK)

			if strings.HasSuffix(path, ".m3u8") {
				if c.Request.Header.Get("proxyMode") == "remote" {
					c.Writer.Write(buf[:readLen])
				} else {
					c.Writer.Write(regexpTs.ReplaceAll(buf[:readLen], []byte(".ts?"+c.Request.URL.RawQuery)))
				}
			} else if strings.HasSuffix(path, ".ts") {
				c.Writer.Write(buf[:readLen])
				fs.Write(buf[:readLen])
			}

			c.Writer.(http.Flusher).Flush()
		}

		return
	}

	if path, err := common.GetHlsFilePath(c.Request.URL.Path); os.IsNotExist(err) && len(path) > 0 {
		transformFile(path, &common.HttpFileSystem{
			Req: func(host string) *http.Request {
				c.Request.URL.Scheme = "http"
				c.Request.Header.Set("proxyMode", "")

				if idx := strings.Index(host, ";"); idx == -1 {
					c.Request.URL.Host = host
				} else {
					c.Request.URL.Host = host[:idx]
					c.Request.Header.Set("proxyMode", host[idx+1:])
				}
				return c.Request
			}(c.GetString("proxyHost")),
		})
	} else {
		transformFile(path, &common.LocalFileSystem{})
	}
}
