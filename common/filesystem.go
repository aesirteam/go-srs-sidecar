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
	Open() (string, error)
	Read(buf []byte) (int, error)
	Close() error
}

type LocalFileSystem struct {
	Path string

	handler *os.File
	reader  *bufio.Reader
}

type HttpFileSystem struct {
	Path   string
	Client func() (*http.Response, error)

	handler *os.File
	reader  io.ReadCloser
	writer  *bufio.Writer
}

func (fs *LocalFileSystem) Open() (path string, err error) {
	path = fs.Path
	if fs.handler, err = os.Open(path); err == nil {
		fs.reader = bufio.NewReader(fs.handler)
	}
	return
}

func (fs *LocalFileSystem) Read(buf []byte) (int, error) {
	return fs.reader.Read(buf)
}

func (fs *LocalFileSystem) WriteTo(w io.Writer) (int64, error) {
	return fs.reader.WriteTo(w)
}

func (fs *LocalFileSystem) Close() error {
	return ioutil.NopCloser(fs.handler).Close()
}

func (fs *HttpFileSystem) Open() (path string, err error) {
	path = fs.Path
	if strings.HasSuffix(path, ".ts") {
		_ = os.MkdirAll(filepath.Dir(path), 0755)

		if fs.handler, err = os.Create(path); err == nil {
			fs.writer = bufio.NewWriter(fs.handler)
		}
	}

	if resp, err := fs.Client(); err == nil {
		fs.reader = resp.Body
	}

	return
}

func (fs *HttpFileSystem) Read(buf []byte) (int, error) {
	return fs.reader.Read(buf)
}

func (fs *HttpFileSystem) Write(data []byte) (nn int, err error) {
	if fs.writer != nil {
		return fs.writer.Write(data)
	}

	return
}

func (fs *HttpFileSystem) Close() error {
	if fs.writer != nil {
		_ = fs.writer.Flush()
	}
	if fs.handler != nil {
		_ = fs.handler.Close()
	}

	return fs.reader.Close()
}
