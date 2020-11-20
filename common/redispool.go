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
	Ip     string `json:"ip"`
	Vhost  string `json:"vhost" binding:"required"`
	App    string `json:"app" binding:"required"`
	Stream string `json:"stream" binding:"required"`
	Param  string `json:"param"`
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
	ClusterOrigin []byte
}

var (
	pool []*redis.Pool
)

func (s *RedisPool) getPool(role string) (*redis.Pool, error) {
	s.once.Do(func() {
		sntnl := &sentinel.Sentinel{
			Addrs:      []string{Conf.SentinelHost + ":" + strconv.Itoa(Conf.SentinelPort)},
			MasterName: Conf.MasterName,
			Dial: func(addr string) (redis.Conn, error) {
				c, err := redis.Dial("tcp", addr)
				if err != nil {
					klog.Fatal(err)
					return nil, err
				}
				return c, nil
			},
		}

		dialDatabase, dialPassword := redis.DialDatabase(Conf.Database), redis.DialPassword(Conf.Password)
		//init master pool
		masterAddr, err := sntnl.MasterAddr()
		if err != nil {
			klog.Fatal(err)
			return
		}

		pool = append(pool, &redis.Pool{
			MaxIdle:     Conf.MaxIdle,
			MaxActive:   Conf.MaxActive,
			IdleTimeout: 240 * time.Second,
			Wait:        true,
			Dial: func() (redis.Conn, error) {
				c, err := redis.Dial("tcp", masterAddr, dialDatabase, dialPassword)
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
		slaveAddrs, err := sntnl.SlaveAddrs()
		if err != nil {
			klog.Fatal(err)
			return
		}

		for _, addr := range slaveAddrs {
			pool = append(pool, &redis.Pool{
				MaxIdle:     Conf.MaxIdle,
				MaxActive:   Conf.MaxActive,
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
	})

	if len(role) == 0 {
		role = "slave"
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

func (s *RedisPool) getAllUserName(accounts []string) (result []string, err error) {
	pool, err := s.getPool("")
	if err != nil {
		return
	}

	client := pool.Get()
	defer release(client)

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

	return
}

func (s *RedisPool) getAllStreamName() (streams []string, err error) {
	pool, err := s.getPool("")
	if err != nil {
		return
	}

	client := pool.Get()
	defer release(client)

	if reply, err := redis.Values(client.Do("SCAN", 0, "MATCH", STREAM_PREFIX+"*", "COUNT", 1<<32-1 /*math.MaxUint32*/)); err == nil {
		arr := reply[1].([]interface{})
		streams = make([]string, len(arr))

		for i, v := range arr {
			streams[i] = string(v.([]byte))
		}
	}

	return
}

func (s *RedisPool) CheckTokenExpire(info *UserInfo) bool {
	return info.TokenExpire-time.Now().Unix() <= 0
}

func (s *RedisPool) RefreshToken(info *UserInfo, ttl int64) (err error) {
	pool, err := s.getPool("master")
	if err != nil {
		return
	}

	client := pool.Get()
	defer release(client)

	if ttl == 0 {
		info.Token = encodeUserToken(info.Account, info.Password)
		ttl = Conf.DefaultTokenExpire
	}

	if obj, err := jsoniter.Marshal(map[string]interface{}{
		"password": info.Password,
		"token":    info.Token,
		"expire":   time.Now().Unix() + ttl,
	}); err == nil {
		_, err = client.Do("HSET", "users", info.Account, obj)
	}

	return
}

func (s *RedisPool) InitAdminUser() string {
	if err := s.AddUser(&UserInfo{
		Account:  "admin",
		Password: Conf.DefaultAdminPasswd,
	}); err != nil {
		klog.Warning(err)
	}

	if info, err := s.GetUserInfo("admin"); err == nil {
		return info.Password
	}

	return ""
}

func (s *RedisPool) TokenAuth(e *WebHookEvent) (errCode int, err error) {
	var (
		key        = STREAM_PREFIX + e.Vhost + "/" + e.App + "/" + e.Stream
		user       string
		token      string
		query      url.Values
		streamInfo *StreamInfo
		userInfo   *UserInfo
		isOwner    bool
	)

	if len(e.Param) > 0 && e.Param[0] == 63 {
		e.Param = e.Param[1:]
	}

	if query, err = url.ParseQuery(e.Param); err != nil {
		goto Error500
	}
	user, token = query.Get("u"), query.Get("t")

	if streamInfo, err = s.GetStreamInfo(key); err != nil {
		goto Error500
	}
	if !streamInfo.Exists {
		errCode = 404
		err = errors.New(`Key '` + key + `' not exists`)
		return
	}

	isOwner = user == streamInfo.Owner

	switch e.Action {
	case "on_publish", "on_unpublish":
		if len(user) == 0 || len(token) == 0 {
			goto Error401
		}

		if !isOwner {
			errCode = 403
			err = errors.New("The publish stream owner fail")
			return
		}

		if userInfo, err = s.GetUserInfo(user); err != nil {
			goto Error500
		}

		if s.CheckTokenExpire(userInfo) || userInfo.Token != token {
			goto Error401
		}

		if e.Action == "on_publish" {
			s.RefreshToken(userInfo, 3600*24*365)

			go func() {
				if streamInfo.Meta.ClusterOrigin, err = jsoniter.Marshal(map[string]map[string]interface{}{
					"query": {
						"ip":     e.Ip,
						"vhost":  e.Vhost,
						"app":    e.App,
						"stream": e.Stream,
					},
					"origin": {
						"ip":    PodIp,
						"port":  1935,
						"vhost": e.Vhost,
					},
				}); err == nil {
					s.UpdateStreamMetadata(key, streamInfo.Meta)
				}
			}()
		} else {
			s.RefreshToken(userInfo, Conf.DefaultTokenExpire)
		}

	case "on_play":
		if streamInfo.Meta.PlaySubscribe {
			if subscribed := func(account string) (b bool) {
				if isOwner || account == "admin" {
					return true
				}

				for _, u := range streamInfo.Users {
					if account == u {
						b = true
						break
					}
				}

				return
			}(user); !subscribed {
				errCode = 403
				err = errors.New("The play stream must subscribed, otherwise don't play")
				return
			}
		}

		if streamInfo.Meta.PlaySecret {
			if len(user) == 0 || len(token) == 0 {
				goto Error401
			}

			if userInfo, err = s.GetUserInfo(user); err != nil {
				goto Error500
			}
			if s.CheckTokenExpire(userInfo) || userInfo.Token != token {
				goto Error401
			}

			if !isOwner {
				s.RefreshToken(userInfo, Conf.DefaultTokenExpire)
			}
		}

		//originIp = jsoniter.Get(streamInfo.Meta.ClusterOrigin, "origin", "ip").ToString()
	default:
		err = errors.New(`Action '` + e.Action + `' fail`)
		goto Error500
	}

	return 200, nil

Error401:
	return 401, errors.New("Unauthorized")

Error500:
	return 500, err
}

func (s *RedisPool) GetUserInfo(account string) (result *UserInfo, err error) {
	if users, err := s.GetUsers([]string{account}); err == nil && len(users) > 0 {
		result = &users[0]
	} else {
		result = &UserInfo{
			Account: account,
		}
	}

	return
}

func (s *RedisPool) GetUsers(accounts []string) (result []UserInfo, err error) {
	if accounts, err = s.getAllUserName(accounts); err != nil {
		return
	}

	pool, err := s.getPool("")
	if err != nil {
		return
	}

	client := pool.Get()
	defer release(client)

	for _, name := range accounts {
		client.Send("HGET", "users", name)
	}

	client.Flush()

	//receive from redis
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

	return
}

func (s *RedisPool) AddUser(info *UserInfo) (err error) {
	var user *UserInfo

	//check user exists
	if user, err = s.GetUserInfo(info.Account); err != nil {
		return
	}
	if user.Exists {
		err = errors.New(`User '` + info.Account + `' already exists`)
		return
	}

	info.Password = genUserPassword(info.Password)

	return s.RefreshToken(info, 0)
}

func (s *RedisPool) DeleteUser(account string) (err error) {
	var user *UserInfo

	//check user exists
	if user, err = s.GetUserInfo(account); err != nil {
		return
	}
	if !user.Exists {
		err = errors.New(`User '` + account + `' not exists`)
		return
	}

	pool, err := s.getPool("master")
	if err != nil {
		return
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

	return
}

func (s *RedisPool) GetStreamInfo(stream string) (result *StreamInfo, err error) {
	if streams, err := s.GetStreams([]string{stream}); err == nil {
		result = &streams[0]
	}

	return
}

func (s *RedisPool) GetStreams(streams []string) (result []StreamInfo, err error) {
	if len(streams) == 0 {
		if streams, err = s.getAllStreamName(); err != nil {
			return
		}
	}

	pool, err := s.getPool("")
	if err != nil {
		return
	}

	client := pool.Get()
	defer release(client)

	for _, key := range streams {
		client.Send("HGETALL", key)
	}

	client.Flush()

	result = make([]StreamInfo, len(streams))

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

	return
}

func (s *RedisPool) NewStream(key, owner string) (result *StreamInfo, err error) {
	if len(owner) == 0 {
		err = errors.New("Owner must define")
		return
	}

	//check stream exists
	if result, err = s.GetStreamInfo(key); err != nil {
		return
	}
	if result.Exists {
		err = errors.New(`Key '` + key + `' already exists`)
		return
	}

	var user *UserInfo

	//check user exists
	if user, err = s.GetUserInfo(owner); err != nil {
		return
	}
	if !user.Exists {
		err = errors.New(`Owner '` + owner + `' not exists`)
		return
	}

	pool, err := s.getPool("master")
	if err != nil {
		return
	}

	client := pool.Get()
	defer release(client)

	//init stream metadata
	if _, err := client.Do("HMSET", key,
		"owner", owner,
		"metadata/play_secret", false,
		"metadata/play_subscribe", false,
	); err == nil {
		result, err = s.GetStreamInfo(key)
	}

	return
}

func (s *RedisPool) SubscribeStream(key string, accounts []string) (result *StreamInfo, err error) {
	//check stream exists
	if result, err = s.GetStreamInfo(key); err != nil {
		return
	}
	if !result.Exists {
		err = errors.New(`Key '` + key + `' not exists`)
		return
	}

	pool, err := s.getPool("master")
	if err != nil {
		return
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

		result, err = s.GetStreamInfo(key)
	}

	return
}

func (s *RedisPool) UpdateStreamMetadata(key string, meta StreamMeta) (result *StreamInfo, err error) {
	//check stream exists
	if result, err = s.GetStreamInfo(key); err != nil {
		return
	}
	if !result.Exists {
		err = errors.New(`Key '` + key + `' not exists`)
		return
	}

	pool, err := s.getPool("master")
	if err != nil {
		return
	}

	client := pool.Get()
	defer release(client)

	var pipeLine int

	client.Send("HMSET", key,
		"metadata/play_secret", meta.PlaySecret,
		"metadata/play_subscribe", meta.PlaySubscribe,
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

func (s *RedisPool) UnsubscribeStream(key string, accounts []string) (result *StreamInfo, err error) {
	//check stream exists
	if result, err = s.GetStreamInfo(key); err != nil {
		return
	}
	if !result.Exists {
		err = errors.New(`Key '` + key + `' not exists`)
		return
	}

	pool, err := s.getPool("master")
	if err != nil {
		return
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

		result, err = s.GetStreamInfo(key)
	}

	return
}

func (s *RedisPool) DeleteStream(key string) (err error) {
	pool, err := s.getPool("master")
	if err != nil {
		return
	}

	client := pool.Get()
	defer release(client)

	_, err = client.Do("DEL", key)

	return
}
