package common

import (
	"errors"
	"github.com/FZambia/sentinel"
	"github.com/gomodule/redigo/redis"
	"github.com/json-iterator/go"
	"k8s.io/klog"
	"net/url"
	"strconv"
	"sync"
	"time"
)

type RedisPool struct {
	once     sync.Once
	sliceIdx int
}

type WebHookEvent struct {
	Action string `json:"action" binding:"required"`
	//ClientId string `json:"client_id"`
	Ip      string `json:"ip" binding:"required"`
	Vhost   string `json:"vhost" binding:"required"`
	App     string `json:"app" binding:"required"`
	Stream  string `json:"stream" binding:"required"`
	Param   string `json:"param"`
	Url     string `json:"url"`
	M3u8Url string `json:"m3u8_url"`
}

type UserInfo struct {
	Account     string
	Exists      bool
	Password    string
	Token       string
	TokenExpire int64
}

type StreamInfo struct {
	Users []string
	StreamDesc
}

type StreamDesc struct {
	Key    string
	Owner  string
	Exists bool
	Meta   StreamMeta
}

type StreamMeta struct {
	PlaySecret    bool
	PlaySubscribe bool
	HlsBackup     bool
	ClusterOrigin []byte
}

var (
	pool []*redis.Pool
)

func (s *RedisPool) getPool(role string) (*redis.Pool, error) {
	s.once.Do(func() {
		dialDatabase, dialPassword := redis.DialDatabase(Conf.RedisDatabase), redis.DialPassword(Conf.RedisPassword)

		switch Conf.RedisMode {
		case "Standalone":
			pool = append(pool, &redis.Pool{
				MaxIdle:     Conf.RedisMaxIdle,
				MaxActive:   Conf.RedisMaxActive,
				IdleTimeout: 240 * time.Second,
				Wait:        true,
				Dial: func() (redis.Conn, error) {
					c, err := redis.Dial("tcp", Conf.RedislHost+":"+strconv.Itoa(Conf.RedisPort), dialDatabase, dialPassword)
					if err != nil {
						klog.Fatal(err)
						return nil, err
					}
					return c, nil
				},
				TestOnBorrow: func(c redis.Conn, t time.Time) (err error) {
					if time.Since(t) < time.Minute {
						return
					}
					if _, err := c.Do("PING"); err != nil {
						klog.Fatal(err)
					}
					return err
				},
			})

		case "Sentinel":
			sntnl := &sentinel.Sentinel{
				Addrs:      []string{Conf.RedislHost + ":" + strconv.Itoa(Conf.RedisPort)},
				MasterName: Conf.RedisMaster,
				Dial: func(addr string) (redis.Conn, error) {
					c, err := redis.Dial("tcp", addr)
					if err != nil {
						klog.Fatal(err)
						return nil, err
					}
					return c, nil
				},
			}

			//init master pool
			addr, err := sntnl.MasterAddr()
			if err != nil {
				klog.Fatal(err)
			}

			pool = append(pool, &redis.Pool{
				MaxIdle:     Conf.RedisMaxIdle,
				MaxActive:   Conf.RedisMaxActive,
				IdleTimeout: 240 * time.Second,
				Wait:        true,
				Dial: func() (redis.Conn, error) {
					c, err := redis.Dial("tcp", addr, dialDatabase, dialPassword)
					if err != nil {
						klog.Fatal(err)
						return nil, err
					}
					return c, nil
				},
				TestOnBorrow: func(c redis.Conn, t time.Time) (err error) {
					if time.Since(t) < time.Minute {
						return
					}
					if _, err := c.Do("PING"); err != nil {
						klog.Fatal(err)
					}
					return err
				},
			})

			//init slaves pool
			slaves, err := sntnl.SlaveAddrs()
			if err != nil {
				klog.Fatal(err)
			}

			for _, addr := range slaves {
				pool = append(pool, &redis.Pool{
					MaxIdle:     Conf.RedisMaxIdle,
					MaxActive:   Conf.RedisMaxActive,
					IdleTimeout: 240 * time.Second,
					Wait:        true,
					Dial: func() (redis.Conn, error) {
						c, err := redis.Dial("tcp", addr, dialDatabase, dialPassword)
						if err != nil {
							klog.Fatal(err)
							return nil, err
						}
						return c, nil
					},
					TestOnBorrow: func(c redis.Conn, t time.Time) (err error) {
						if time.Since(t) < time.Minute {
							return
						}
						if _, err := c.Do("PING"); err != nil {
							klog.Fatal(err)
						}
						return err
					},
				})
			}

		default:
			klog.Fatal("Redis only support Standalone/Sentinel mode")
		}
	})

	if Conf.RedisMode == "Standalone" {
		role = "master"
	}

	if role == "master" {
		return pool[0], nil
	} else {
		return s.roundRobinBalance(pool[1:])
	}
}

func (s *RedisPool) roundRobinBalance(insts []*redis.Pool) (inst *redis.Pool, err error) {
	if len(insts) == 0 {
		err = errors.New("No instance")
		return
	}

	lens := len(insts)
	if s.sliceIdx >= lens {
		s.sliceIdx = 0
	}

	inst = insts[s.sliceIdx]
	s.sliceIdx = (s.sliceIdx + 1) % lens
	return
}

func release(client redis.Conn) {
	if client != nil {
		client.Close()
	}
}

func (s *RedisPool) Close() {
	for _, slice := range pool {
		if slice != nil {
			slice.Close()
		}
	}
}

func (s *RedisPool) getAllUserName(accounts []string) ([]string, error) {
	pool, err := s.getPool("")
	if err != nil {
		return nil, err
	}

	client := pool.Get()
	defer release(client)

	var result []string

	if len(accounts) == 0 {
		if reply, err := client.Do("HGETALL", "users"); err == nil {
			arr := reply.([]interface{})

			for i := 0; i < len(arr); i += 2 {
				result = append(result, string(arr[i].([]byte)))
			}
		}
	} else {
		for _, name := range accounts {
			client.Send("HEXISTS", "users", name)
		}

		client.Flush()

		//receive from redis
		for i := 0; i < len(accounts); i++ {
			if exists, err := redis.Bool(client.Receive()); err == nil && exists {
				result = append(result, accounts[i])
			}
		}
	}

	return result, nil
}

func (s *RedisPool) getAllStreamName() ([]string, error) {
	pool, err := s.getPool("")
	if err != nil {
		return nil, err
	}

	client := pool.Get()
	defer release(client)

	var streams []string

	if reply, err := redis.Values(client.Do("SCAN", 0, "MATCH", STREAM_PREFIX+"*", "COUNT", 1<<32-1 /*math.MaxUint32*/)); err == nil {
		arr := reply[1].([]interface{})
		streams = make([]string, len(arr))

		for i, v := range arr {
			streams[i] = string(v.([]byte))
		}
	}

	return streams, nil
}

func (s *RedisPool) RefreshToken(info *UserInfo) (*UserInfo, error) {
	pool, err := s.getPool("master")
	if err != nil {
		return nil, err
	}

	client := pool.Get()
	defer release(client)

	if info.TokenExpire-time.Now().Unix() <= 0 {
		info.Token = encodeUserToken(info.Account, info.Password)
	}

	if obj, err := jsoniter.Marshal(map[string]interface{}{
		"password": info.Password,
		"token":    info.Token,
		"expire":   time.Now().Unix() + Conf.DefaultTokenExpire,
	}); err == nil {
		_, err = client.Do("HSET", "users", info.Account, obj)
	}

	return info, nil
}

func (s *RedisPool) InitAdminUser() string {
	var (
		info *UserInfo
		err  error
	)

	if info, err = s.AddUser(&UserInfo{
		Account:  "admin",
		Password: Conf.DefaultAdminPasswd,
	}); err != nil {
		klog.Warning(err)
	}

	return info.Password
}
func (s *RedisPool) TokenAuth(e *WebHookEvent) (int, string, *StreamInfo) {
	var (
		user, token string
		key         = STREAM_PREFIX + e.Vhost + "/" + e.App + "/" + e.Stream
	)

	if len(e.Param) > 0 && e.Param[0] == 63 {
		e.Param = e.Param[1:]
	}

	if query, err := url.ParseQuery(e.Param); err != nil {
		return 500, err.Error(), nil
	} else {
		user, token = query.Get("u"), query.Get("t")
	}

	sc := make(chan func() (*StreamInfo, error), 1)
	defer close(sc)

	go func() {
		sc <- func() (*StreamInfo, error) { return s.GetStreamInfo(key) }
	}()

	if streamInfo, err := (<-sc)(); err != nil {
		return 500, err.Error(), nil
	} else {
		if !streamInfo.Exists {
			return 404, `Key "` + key + `" not exists`, nil
		}

		switch e.Action {
		case "on_publish", "on_hls":
			if len(user) == 0 || len(token) == 0 {
				return 401, "Unauthorized", streamInfo
			}

			if !(user == streamInfo.Owner) {
				return 403, "The stream owner not match", streamInfo
			}

			uc := make(chan func() (*UserInfo, error), 1)
			defer close(uc)

			go func() {
				uc <- func() (*UserInfo, error) { return s.GetUserInfo(user) }
			}()

			if userInfo, err := (<-uc)(); err != nil {
				return 500, err.Error(), streamInfo
			} else {
				if userInfo.Token != token || userInfo.TokenExpire-time.Now().Unix() <= 0 {
					return 401, "Unauthorized", streamInfo
				}

				if e.Action == "on_publish" {
					go func(meta StreamMeta) {
						if meta.ClusterOrigin, err = jsoniter.Marshal(map[string]map[string]interface{}{
							"query":  {"ip": e.Ip, "vhost": e.Vhost, "app": e.App, "stream": e.Stream},
							"origin": {"ip": PodIp, "port": 1935, "vhost": e.Vhost},
						}); err == nil {
							s.UpdateStreamMetadata(key, meta)
						}
					}(streamInfo.Meta)
				}

				go s.RefreshToken(userInfo)
			}
		case "on_play":
			if streamInfo.Meta.PlaySubscribe {
				if subscribed := func() (b bool) {
					if user == streamInfo.Owner || user == "admin" {
						return true
					}

					for _, u := range streamInfo.Users {
						if b = user == u; b {
							break
						}
					}

					return
				}(); !subscribed {
					return 403, "The stream must subscribed, otherwise don't play", streamInfo
				}
			}

			if streamInfo.Meta.PlaySecret {
				if len(user) == 0 || len(token) == 0 {
					return 401, "Unauthorized", streamInfo
				}

				uc := make(chan func() (*UserInfo, error), 1)
				defer close(uc)

				go func() {
					uc <- func() (*UserInfo, error) { return s.GetUserInfo(user) }
				}()

				if userInfo, err := (<-uc)(); err != nil {
					return 500, err.Error(), streamInfo
				} else {
					if userInfo.Token != token || userInfo.TokenExpire-time.Now().Unix() <= 0 {
						return 401, "Unauthorized", streamInfo
					}

					go s.RefreshToken(userInfo)
				}
			}
		}

		return 200, "", streamInfo
	}
}

func (s *RedisPool) GetUserInfo(account string) (*UserInfo, error) {
	if users, err := s.GetUsers([]string{account}); err == nil && len(users) > 0 {
		return &users[0], nil
	} else {
		return &UserInfo{Account: account}, nil
	}
}

func (s *RedisPool) GetUsers(accounts []string) ([]UserInfo, error) {
	var err error

	if accounts, err = s.getAllUserName(accounts); err != nil {
		return nil, err
	}

	pool, err := s.getPool("")
	if err != nil {
		return nil, err
	}

	client := pool.Get()
	defer release(client)

	for _, name := range accounts {
		client.Send("HGET", "users", name)
	}

	client.Flush()

	var result []UserInfo

	for _, name := range accounts {
		if v, err := redis.Bytes(client.Receive()); err == nil {
			if body := jsoniter.Get(v); body.LastError() == nil {
				result = append(result, UserInfo{
					Account:     name,
					Password:    body.Get("password").ToString(),
					Exists:      true,
					Token:       body.Get("token").ToString(),
					TokenExpire: body.Get("expire").ToInt64(),
				})
			}
		}
	}

	return result, nil
}

func (s *RedisPool) AddUser(info *UserInfo) (*UserInfo, error) {
	var (
		user *UserInfo
		err  error
	)

	//check user exists
	if user, err = s.GetUserInfo(info.Account); err != nil {
		return nil, err
	}

	if !user.Exists {
		if len(info.Password) == 0 {
			info.Password = randString(16)
		}
		//return nil, errors.New(`User '` + info.Account + `' already exists`)
	}

	return s.RefreshToken(info)
}

func (s *RedisPool) DeleteUser(account string) error {
	var (
		user *UserInfo
		err  error
	)

	//check user exists
	if user, err = s.GetUserInfo(account); err != nil {
		return err
	}

	if !user.Exists {
		return errors.New(`User '` + account + `' not exists`)
	}

	pool, err := s.getPool("master")
	if err != nil {
		return err
	}

	client := pool.Get()
	defer release(client)

	if streams, err := s.getAllStreamName(); err == nil {
		var pipeLine int
		for _, key := range streams {
			client.Send("HDEL", key, account)
			pipeLine++
		}

		client.Send("HDEL", "users", account)
		pipeLine++

		client.Flush()

		//receive from redis
		for i := 0; i < pipeLine; i++ {
			if _, err = client.Receive(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *RedisPool) GetStreamInfo(stream string) (*StreamInfo, error) {
	if streams, err := s.GetStreams([]string{stream}); err == nil {
		return &streams[0], nil
	} else {
		return nil, err
	}
}

func (s *RedisPool) GetStreams(streams []string) ([]StreamInfo, error) {
	var err error

	if len(streams) == 0 {
		if streams, err = s.getAllStreamName(); err != nil {
			return nil, err
		}
	}

	pool, err := s.getPool("")
	if err != nil {
		return nil, err
	}

	client := pool.Get()
	defer release(client)

	for _, key := range streams {
		client.Send("HGETALL", key)
	}

	client.Flush()

	result := make([]StreamInfo, len(streams))

	//receive from redis
	for j, key := range streams {
		if reply, err := client.Receive(); err == nil {
			result[j].Key = key
			result[j].Users = []string{}
			result[j].Meta = StreamMeta{}

			arr := reply.([]interface{})
			result[j].Exists = len(arr) > 0

			for k := 0; k < len(arr); k += 2 {
				field := string(arr[k].([]byte))
				switch field {
				case "metadata/play_secret":
					result[j].Meta.PlaySecret = arr[k+1].([]byte)[0] == 49
				case "metadata/play_subscribe":
					result[j].Meta.PlaySubscribe = arr[k+1].([]byte)[0] == 49
				case "metadata/hls_backup":
					result[j].Meta.HlsBackup = arr[k+1].([]byte)[0] == 49
				case "metadata/cluster_origin":
					result[j].Meta.ClusterOrigin = arr[k+1].([]byte)
				case "owner":
					result[j].Owner = string(arr[k+1].([]byte))
				default:
					result[j].Users = append(result[j].Users, field)
				}
			}
		}
	}

	return result, nil
}

func (s *RedisPool) NewStream(key, owner string) (*StreamInfo, error) {
	if len(owner) == 0 {
		return nil, errors.New("Owner must define")
	}

	var (
		result *StreamInfo
		user   *UserInfo
		err    error
	)

	//check stream exists
	if result, err = s.GetStreamInfo(key); err != nil {
		return nil, err
	}

	if result.Exists {
		return nil, errors.New(`Key '` + key + `' already exists`)
	}

	//check user exists
	if user, err = s.GetUserInfo(owner); err != nil {
		return nil, err
	}
	if !user.Exists {
		return nil, errors.New(`Owner '` + owner + `' not exists`)
	}

	pool, err := s.getPool("master")
	if err != nil {
		return nil, err
	}

	client := pool.Get()
	defer release(client)

	//init stream metadata
	if _, err := client.Do("HMSET", key,
		"owner", owner,
		"metadata/play_secret", false,
		"metadata/play_subscribe", false,
	); err != nil {
		return nil, err
	}

	return s.GetStreamInfo(key)
}

func (s *RedisPool) SubscribeStream(key string, accounts []string) (*StreamInfo, error) {
	var (
		result *StreamInfo
		err    error
	)

	//check stream exists
	if result, err = s.GetStreamInfo(key); err != nil {
		return nil, err
	}

	if !result.Exists {
		return nil, errors.New(`Key '` + key + `' not exists`)
	}

	pool, err := s.getPool("master")
	if err != nil {
		return nil, err
	}

	client := pool.Get()
	defer release(client)

	if accounts, err := s.getAllUserName(accounts); err == nil {
		for _, name := range accounts {
			client.Send("HSET", key, name, true)
		}

		client.Flush()

		//receive from redis
		for i := 0; i < len(accounts); i++ {
			if _, err = client.Receive(); err != nil {
				return nil, err
			}
		}
	}

	return s.GetStreamInfo(key)
}

func (s *RedisPool) UpdateStreamMetadata(key string, meta StreamMeta) (*StreamInfo, error) {
	var (
		result *StreamInfo
		err    error
	)

	//check stream exists
	if result, err = s.GetStreamInfo(key); err != nil {
		return nil, err
	}

	if !result.Exists {
		return nil, errors.New(`Key '` + key + `' not exists`)
	}

	pool, err := s.getPool("master")
	if err != nil {
		return nil, err
	}

	client := pool.Get()
	defer release(client)

	var pipeLine int

	client.Send("HMSET", key,
		"metadata/play_secret", meta.PlaySecret,
		"metadata/play_subscribe", meta.PlaySubscribe,
		"metadata/hls_backup", meta.HlsBackup,
	)
	pipeLine++

	if len(meta.ClusterOrigin) > 0 {
		client.Send("HSET", key, "metadata/cluster_origin", meta.ClusterOrigin)
		pipeLine++
	}

	client.Flush()

	for i := 0; i < pipeLine; i++ {
		client.Receive()
	}

	return s.GetStreamInfo(key)
}

func (s *RedisPool) UnsubscribeStream(key string, accounts []string) (*StreamInfo, error) {
	var (
		result *StreamInfo
		err    error
	)

	//check stream exists
	if result, err = s.GetStreamInfo(key); err != nil {
		return nil, err
	}

	if !result.Exists {
		return nil, errors.New(`Key '` + key + `' not exists`)
	}

	pool, err := s.getPool("master")
	if err != nil {
		return nil, err
	}

	client := pool.Get()
	defer release(client)

	if accounts, err = s.getAllUserName(accounts); err == nil {
		var pipeLine int

		for _, user := range accounts {
			if user != result.Owner && user != "admin" {
				client.Send("HDEL", key, user)
				pipeLine++
			}
		}

		client.Flush()

		//receive from redis
		for i := 0; i < pipeLine; i++ {
			if _, err = client.Receive(); err != nil {
				return nil, err
			}
		}
	}

	return s.GetStreamInfo(key)
}

func (s *RedisPool) DeleteStream(key string) error {
	pool, err := s.getPool("master")
	if err != nil {
		return err
	}

	client := pool.Get()
	defer release(client)

	if _, err := client.Do("DEL", key); err != nil {
		return err
	}

	return nil
}
