package common

import (
	"github.com/fsnotify/fsnotify"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

func removeExpireFile(root string, ttl int64) {
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if time.Now().Unix()-info.ModTime().Unix() >= ttl {
			os.Remove(path)
		}
		return nil
	})
}

func NewWatcher() *LocalFileSystem {
	return &LocalFileSystem{
		CustomConfig: Conf,
	}
}

func (fs *LocalFileSystem) ConfigFile(authEnc string) {
	reload := func() error {
		transport := http.Transport{}
		resp, err := transport.RoundTrip(&http.Request{
			Method: "GET",
			URL: &url.URL{
				Scheme:   "http",
				Host:     fs.SrsApiServer,
				Path:     "/api/v1/raw",
				RawQuery: "rpc=reload&scope=configmap",
			},
			Header: http.Header{
				"X-Forwarded-For": {PodIp},
				"Authorization":   {authEnc},
			},
		})
		if err != nil {
			return err
		}

		resp.Body.Close()
		return nil
	}

	//first
	_ = reload()

	if watcher, err := fsnotify.NewWatcher(); err == nil {
		defer watcher.Close()

		path := fs.SrsCfgFile

		if path, err = filepath.Abs(path); err != nil {
			Logger.Warn("Watcher[ConfigFile]: ", err.Error())
			return
		}

		done := make(chan bool)
		go func() {
			for {
				select {
				case event, ok := <-watcher.Events:
					if !ok {
						return
					}
					if event.Op&fsnotify.CloseWrite == fsnotify.CloseWrite {
						_ = reload()
					}
				case err, ok := <-watcher.Errors:
					if !ok {
						Logger.Warn("Watcher[ConfigFile]: ", err.Error())
						return
					}
				}
			}
		}()

		if err = watcher.Add(path); err != nil {
			Logger.Warn("Watcher[ConfigFile]: ", err.Error())
			return
		}

		Logger.Info("Watcher[ConfigFile]: ", "started")
		<-done
	}
}

func (fs *LocalFileSystem) MediaFile(root string) {
	if len(root) == 0 {
		root = fs.SrsHlsPath
	}

	if watcher, err := fsnotify.NewWatcher(); err == nil {
		defer watcher.Close()

		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if info.IsDir() {
				path, err := filepath.Abs(path)
				if err != nil {
					return err
				}
				err = watcher.Add(path)
				if err != nil {
					return err
				}
			}
			return nil
		})

		done := make(chan bool)
		go func() {
			for {
				select {
				case event, ok := <-watcher.Events:
					if !ok {
						return
					}
					if event.Op&fsnotify.Create == fsnotify.Create {
						if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
							_ = watcher.Add(event.Name)
						}
					}
					if event.Op&fsnotify.CloseWrite == fsnotify.CloseWrite {
						removeExpireFile(filepath.Dir(event.Name), fs.SrsHlsExpire)
					}
				case err, ok := <-watcher.Errors:
					if !ok {
						Logger.Warn("Watcher[MediaFile]: ", err.Error())
						return
					}
				}
			}
		}()

		Logger.Info("Watcher[MediaFile]: ", "started")
		<-done
	}
}
