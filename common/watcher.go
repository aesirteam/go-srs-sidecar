package common

import (
	"github.com/fsnotify/fsnotify"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

//func fileDiff(path, md5Old string) (b bool, md5Sum string) {
//	md5Sum = md5Old
//
//	f, err := os.Open(path)
//	if err != nil { return }
//	defer f.Close()
//
//	hash := md5.New()
//	_, err = io.Copy(hash, f)
//	if err != nil { return }
//	hashInBytes := hash.Sum(nil)[:16]
//
//	if md5New := hex.EncodeToString(hashInBytes); md5New != md5Old {
//		md5Sum = md5New
//		b = true
//	}
//
//	return
//}

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
	//var md5Sum	string
	//
	//reload := func() error {
	//	var ok	bool
	//	if ok, md5Sum = fileDiff(w.SrsCfgFile, md5Sum); ok {
	//		transport := http.Transport{}
	//		resp, err := transport.RoundTrip(&http.Request{
	//			Method:		"GET",
	//			URL:		&url.URL{
	//				Scheme:     "http",
	//				Host:       w.SrsApiServer,
	//				Path:       "/api/v1/raw",
	//				RawQuery:	"rpc=reload&scope=configmap",
	//			},
	//			Header:		http.Header{
	//				"Authorization":	{"Basic " + authEnc},
	//			},
	//		})
	//		if err != nil { return err }
	//		resp.Body.Close()
	//	}
	//
	//	return nil
	//}

	reload := func() error {
		transport := http.Transport{}
		if resp, err := transport.RoundTrip(&http.Request{
			Method: "GET",
			URL: &url.URL{
				Scheme:   "http",
				Host:     fs.SrsApiServer,
				Path:     "/api/v1/raw",
				RawQuery: "rpc=reload&scope=configmap",
			},
			Header: http.Header{
				"X-Forwarded-For": {PodIp},
				"Authorization":   {"Basic " + authEnc},
			},
		}); err != nil {
			return err
		} else {
			resp.Body.Close()
			return nil
		}
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
