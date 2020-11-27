package common

import (
	"github.com/fsnotify/fsnotify"
	"k8s.io/klog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type WatcherDaemon struct{}

func removeExpireFile(root string, ttl int64) {
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if time.Now().Unix()-info.ModTime().Unix() >= ttl {
			os.Remove(path)
		}
		return nil
	})
}

func NewWatcher() *WatcherDaemon {
	return &WatcherDaemon{}
}

func (fs *WatcherDaemon) ConfigFile(user, password string) {
	reload := func() error {
		resp, err := (&http.Client{}).Do(&http.Request{
			Method: "GET",
			URL: &url.URL{
				Scheme:   "http",
				Host:     Conf.SrsApiServer,
				Path:     "/api/v1/raw",
				RawQuery: "rpc=reload&scope=configmap",
			},
			Header: http.Header{
				"X-Forwarded-For": {PodIp},
				"Authorization":   {genHeaderAuthorization(user, password)},
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
		defer func() { _ = watcher.Close() }()

		path := Conf.SrsCfgFile

		if path, err = filepath.Abs(path); err != nil {
			klog.Warning("ConfigFileWatcher: ", err.Error())
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
						klog.Warning("ConfigFileWatcher: ", err.Error())
						return
					}
				}
			}
		}()

		if err = watcher.Add(path); err != nil {
			klog.Warning("ConfigFileWatcher: ", err.Error())
			return
		}

		klog.Info("ConfigFileWatcher: ", "started")
		<-done
	}
}

func (fs *WatcherDaemon) MediaFile(root string) {
	if len(root) == 0 {
		root = Conf.SrsHlsPath
	}

	if watcher, err := fsnotify.NewWatcher(); err == nil {
		defer func() { _ = watcher.Close() }()

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
						removeExpireFile(filepath.Dir(event.Name), Conf.SrsHlsExpire)
					}
				case err, ok := <-watcher.Errors:
					if !ok {
						klog.Warning("MediaFileWatcher: ", err.Error())
						return
					}
				}
			}
		}()
		klog.Info("MediaFileWatcher: ", "started")
		<-done
	}
}
