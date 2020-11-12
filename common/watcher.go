package common

import (
	"github.com/caarlos0/env/v6"
	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type Watcher struct {
	CustomConfig
	LocalFileSystem
}

func init() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	log.SetOutput(os.Stdout)

	//log.SetLevel(log.WarnLevel)
}

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

func NewWatcher() *Watcher {
	w := Watcher{}
	if err := env.Parse(&w); err != nil {
		return nil
	}
	return &w
}

func (w *Watcher) ConfigFile(authEnc string) {
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
				Host:     w.SrsApiServer,
				Path:     "/api/v1/raw",
				RawQuery: "rpc=reload&scope=configmap",
			},
			Header: http.Header{
				"Authorization": {"Basic " + authEnc},
			},
		}); err != nil {
			return err
		} else {
			resp.Body.Close()
			return nil
		}
	}

	//first
	reload()

	if watcher, err := fsnotify.NewWatcher(); err == nil {
		defer watcher.Close()

		path := w.SrsCfgFile

		if path, err = filepath.Abs(path); err != nil {
			log.Warn("Watcher[ConfigFile]: ", err.Error())
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
					//if event.Op&fsnotify.Write == fsnotify.Write {
					//	reload()
					//}
					if event.Op&fsnotify.CloseWrite == fsnotify.CloseWrite {
						reload()
					}
				case err, ok := <-watcher.Errors:
					if !ok {
						log.Warn("Watcher[ConfigFile]: ", err.Error())
						return
					}
				}
			}
		}()

		if err = watcher.Add(path); err != nil {
			log.Warn("Watcher[ConfigFile]: ", err.Error())
			return
		}

		log.Info("Watcher[ConfigFile]: ", "started")
		<-done
	}
}

func (w *Watcher) MediaFile(root string) {
	if len(root) == 0 {
		root = w.SrsHlsPath
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
							watcher.Add(event.Name)
						}
					}
					if event.Op&fsnotify.CloseWrite == fsnotify.CloseWrite {
						removeExpireFile(filepath.Dir(event.Name), w.SrsHlsExpire)
					}
				case err, ok := <-watcher.Errors:
					if !ok {
						log.Warn("Watcher[MediaFile]: ", err.Error())
						return
					}
				}
			}
		}()

		log.Info("Watcher[MediaFile]: ", "started")
		<-done
	}
}
