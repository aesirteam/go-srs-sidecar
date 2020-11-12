package common

import (
	"bufio"
	"github.com/caarlos0/env/v6"
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
	CustomConfig

	handler *os.File
	*bufio.Reader
}

func GetHlsFilePath(path string) (string, error) {
	conf := CustomConfig{}
	if err := env.Parse(&conf); err != nil {
		return "", err
	}
	path = conf.SrsHlsPath + path
	_, err := os.Stat(path)

	return path, err
}

func GetCfgFilePath() string {
	conf := CustomConfig{}
	if err := env.Parse(&conf); err != nil {
		return ""
	}
	return conf.SrsCfgFile
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

type HttpFileSystem struct {
	Req *http.Request

	resp    *http.Response
	handler *os.File

	*bufio.Reader
	*bufio.Writer
}

func (fs *HttpFileSystem) Open(path string) (err error) {
	if strings.HasSuffix(path, ".ts") {
		os.MkdirAll(filepath.Dir(path), 0755)

		if fs.handler, err = os.Create(path); err == nil {
			fs.Writer = bufio.NewWriter(fs.handler)
		}
	}

	transport := http.Transport{}
	if fs.resp, err = transport.RoundTrip(fs.Req); err == nil {
		fs.Reader = bufio.NewReader(fs.resp.Body)
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
	if fs.Writer != nil && fs.handler != nil {
		fs.Writer.Flush()
		fs.handler.Close()
	}

	return fs.resp.Body.Close()
}

//type S3FileSystem struct {
//	s3					*S3Client
//
//	handler				*minio.Object
//
//	*bufio.Reader
//}

//func (fs *S3FileSystem) Open(path string) (err error) {
//	if fs.handler, err = fs.s3.GetObject(path); err == nil {
//		fs.Reader = bufio.NewReader(fs.handler)
//	}
//	return
//}
//
//func (fs *S3FileSystem) Read(p []byte) (int, error) {
//	return fs.Reader.Read(p)
//}
//
//func (fs *S3FileSystem) Write(p []byte) (int, error) {
//	return 0, nil
//}
//
//func (fs *S3FileSystem) Close()	error {
//	return fs.handler.Close()
//}
