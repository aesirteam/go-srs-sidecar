package routes

import (
	"github.com/aesirteam/go-srs-sidecar/common"
	"github.com/gin-gonic/gin"
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
)

type App interface {
	Run(addr string)
}

func writeHandlerFunc(c *gin.Context) {
	transformFile := func(path string, fs common.FileSystem) {
		if err := fs.Open(path); err != nil {
			return
		}
		defer fs.Close()

		var (
			err     error
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
			c.Request.Header.Set("proxyMode", host[idx+1:])
			return host[:idx]
		}
	}(c.GetString("proxyHost"))

	path := common.Conf.SrsHlsPath + c.Request.URL.Path

	if _, err := os.Stat(path); os.IsNotExist(err) {
		transformFile(path, &common.HttpFileSystem{Req: c.Request})
	} else {
		if c.Request.Header.Get("proxyMode") == "remote" {
			c.Request.URL.Path = "/verify" + c.Request.URL.Path

			transport := http.Transport{}
			if resp, err := transport.RoundTrip(c.Request); err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			} else if resp.StatusCode != http.StatusOK {
				c.AbortWithStatus(resp.StatusCode)
				return
			}
		}

		transformFile(path, &common.LocalFileSystem{})
	}
}
