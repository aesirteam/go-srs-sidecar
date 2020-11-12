package common

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"github.com/FZambia/sentinel"
	"github.com/caarlos0/env/v6"
	"github.com/gomodule/redigo/redis"
	jsoniter "github.com/json-iterator/go"
	log "github.com/sirupsen/logrus"
	"math"
	"math/rand"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"time"
)

type RedisPool struct {
	CustomConfig

	sliceIdx int
}

type WebHookEvent struct {
	Action   string `json:"action" binding:"required"`
	ClientId string `json:"client_id"`
	Ip       string `json:"ip"`
	Vhost    string `json:"vhost" binding:"required"`
	App      string `json:"app" binding:"required"`
	Stream   string `json:"stream" binding:"required"`
	Param    string `json:"param"`
}

type UserInfo struct {
	Account     string
	Exists      bool
	Password    string
	Token       string
	TokenExpire int64
}

type UserInfoBody map[string]interface{}

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

type ClusterOriginBody map[string]map[string]interface{}

var (
	pool []*redis.Pool
	json = jsoniter.ConfigCompatibleWithStandardLibrary
)

func init() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	log.SetOutput(os.Stdout)

	//log.SetLevel(log.WarnLevel)
}

func EncodeUserToken(user, password, nonce string) string {
	if len(nonce) == 0 {
		b := make([]byte, 8)
		for i := range b {
			b[i] = LETTER_BYTES[rand.Intn(len(LETTER_BYTES))]
		}
		nonce = string(b)
	}

	h := md5.New()
	h.Write([]byte(user + ":" + password + "@" + nonce))
	return hex.EncodeToString(h.Sum(nil)) + nonce
}

func (s *RedisPool) getPool(role string) (*redis.Pool, error) {
	s.once.Do(func() {
		if err := env.Parse(s); err != nil {
			return
		}
		sntnl := &sentinel.Sentinel{
			Addrs:      []string{s.SentinelHost + ":" + strconv.Itoa(s.SentinelPort)},
			MasterName: s.MasterName,
			Dial: func(addr string) (redis.Conn, error) {
				c, err := redis.Dial("tcp", addr)
				if err != nil {
					return nil, err
				}
				return c, nil
			},
		}

		//init master pool
		masterAddr, err := sntnl.MasterAddr()
		if err != nil {
			return
		}

		pool = append(pool, &redis.Pool{
			MaxIdle:     s.MaxIdle,
			MaxActive:   s.MaxActive,
			IdleTimeout: 240 * time.Second,
			Wait:        true,
			Dial: func() (redis.Conn, error) {
				c, err := redis.Dial("tcp", masterAddr, redis.DialDatabase(s.Database), redis.DialPassword(s.Password))
				if err != nil {
					return nil, err
				}
				return c, nil
			},
			TestOnBorrow: func(c redis.Conn, t time.Time) error {
				if time.Since(t) < time.Minute {
					return nil
				}
				_, err := c.Do("PING")
				return err
			},
		})

		//init slaves pool
		slaveAddrs, err := sntnl.SlaveAddrs()
		if err != nil {
			return
		}

		for _, addr := range slaveAddrs {
			pool = append(pool, &redis.Pool{
				MaxIdle:     s.MaxIdle,
				MaxActive:   s.MaxActive,
				IdleTimeout: 240 * time.Second,
				Wait:        true,
				Dial: func() (redis.Conn, error) {
					c, err := redis.Dial("tcp", addr, redis.DialDatabase(s.Database), redis.DialPassword(s.Password))
					if err != nil {
						return nil, err
					}
					return c, nil
				},
				TestOnBorrow: func(c redis.Conn, t time.Time) error {
					if time.Since(t) < time.Minute {
						return nil
					}
					_, err := c.Do("PING")
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

func execCommand(ch chan string, name string, arg ...string) {
	cmd := exec.Command(name, arg...)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		ch <- out.String()[:out.Len()-1]
		return
	}

	ch <- ""
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

	if reply, err := redis.Values(client.Do("SCAN", 0, "MATCH", STREAM_PREFIX+"*", "COUNT", math.MaxUint32)); err == nil {
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

	if obj, err := json.Marshal(UserInfoBody{
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
		Password: s.DefaultAdminPasswd,
	}); err != nil {
		log.Warn(err.Error())
	}

	if info, err := s.GetUserInfo("admin"); err == nil {
		return info.Password
	}

	return ""
}

func (s *RedisPool) TokenAuth(e *WebHookEvent) (errCode int, err error, originIp string) {
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

		ttl := s.DefaultTokenExpire

		if e.Action == "on_publish" {
			ttl = 3600 * 24 * 365
			go func() {
				ch := make(chan string)
				defer close(ch)

				//execCommand(ch, "hostname", "-f")
				execCommand(ch, "hostname", "-i")

				if streamInfo.Meta.ClusterOrigin, err = json.Marshal(ClusterOriginBody{
					"query": {
						"ip":     e.Ip,
						"vhost":  e.Vhost,
						"app":    e.App,
						"stream": e.Stream,
					},
					"origin": {
						//"node":  <-ch,
						"ip":    <-ch,
						"port":  1935,
						"vhost": e.Vhost,
					},
				}); err == nil {
					s.UpdateStreamMetadata(key, streamInfo.Meta)
				}
			}()
		}

		s.RefreshToken(userInfo, ttl)

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
				s.RefreshToken(userInfo, s.DefaultTokenExpire)
			}
		}

		var body ClusterOriginBody
		if err := json.Unmarshal(streamInfo.Meta.ClusterOrigin, &body); err != nil {
			goto Error500
		}

		originIp = body["origin"]["ip"].(string)
	default:
		err = errors.New(`Action '` + e.Action + `' fail`)
		goto Error500
	}

	return 200, nil, originIp

Error401:
	return 401, errors.New("Unauthorized"), ""

Error500:
	return 500, err, ""
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
			var body UserInfoBody
			if err := json.Unmarshal(v, &body); err == nil {
				result = append(result, UserInfo{
					Account:     name,
					Password:    body["password"].(string),
					Exists:      true,
					Token:       body["token"].(string),
					TokenExpire: int64(body["expire"].(float64)),
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

	pool, err := s.getPool("master")
	if err != nil {
		return
	}

	client := pool.Get()
	defer release(client)

	password := func() string {
		if len(info.Password) == 0 {
			b := make([]byte, 16)
			for i := range b {
				b[i] = PASSWD_BYTES[rand.Intn(len(PASSWD_BYTES))]
			}
			return string(b)
		}
		return info.Password
	}()

	if obj, err := json.Marshal(UserInfoBody{
		"password": password,
		"token":    EncodeUserToken(info.Account, password, ""),
		"expire":   time.Now().Unix() + s.DefaultTokenExpire,
	}); err == nil {
		_, err = client.Do("HSET", "users", info.Account, obj)
	}

	return
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
