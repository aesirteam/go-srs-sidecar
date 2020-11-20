package common

import (
	"bufio"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type FileSystem interface {
	Open(path string) error
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

type LocalFileSystem struct {
	handler *os.File
	*bufio.Reader

	CustomConfig
}

type HttpFileSystem struct {
	Req  *http.Request
	Resp *http.Response

	handler *os.File
	*bufio.Reader
	*bufio.Writer

	CustomConfig
}

func (fs *LocalFileSystem) Open(path string) (err error) {
	if fs.handler, err = os.Open(path); err == nil {
		fs.Reader = bufio.NewReader(fs.handler)
	}
	return
}

func (fs *LocalFileSystem) Read(p []byte) (int, error) {
	return fs.Reader.Read(p)
}

func (fs *LocalFileSystem) Write(p []byte) (int, error) {
	_ = p
	return 0, nil
}

func (fs *LocalFileSystem) WriteTo(w io.Writer) (int64, error) {
	return fs.Reader.WriteTo(w)
}

func (fs *LocalFileSystem) Close() error {
	return ioutil.NopCloser(fs.handler).Close()
}

func (fs *HttpFileSystem) Open(path string) (err error) {
	if strings.HasSuffix(path, ".ts") {
		_ = os.MkdirAll(filepath.Dir(path), 0755)

		if fs.handler, err = os.Create(path); err == nil {
			fs.Writer = bufio.NewWriter(fs.handler)
		}
	}

	transport := http.Transport{}
	if fs.Resp, err = transport.RoundTrip(fs.Req); err == nil {
		fs.Reader = bufio.NewReader(fs.Resp.Body)
	}

	return
}

func (fs *HttpFileSystem) Read(p []byte) (int, error) {
	return fs.Reader.Read(p)
}

func (fs *HttpFileSystem) Write(p []byte) (nn int, err error) {
	if fs.Writer == nil {
		return
	}
	return fs.Writer.Write(p)
}

func (fs *HttpFileSystem) Close() error {
	if fs.Writer != nil {
		_ = fs.Writer.Flush()
	}
	if fs.handler != nil {
		_ = fs.handler.Close()
	}

	return fs.Resp.Body.Close()
}
