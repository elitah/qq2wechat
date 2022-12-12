package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/elitah/utils/exepath"
	"github.com/elitah/utils/logs"

	"github.com/Mrs4s/MiraiGo/client"
	"github.com/Mrs4s/MiraiGo/message"
	"github.com/astaxie/beego/httplib"
	"github.com/robfig/cron/v3"
)

var (
	exeDir = exepath.GetExeDir()

	gCron *cron.Cron

	qywx = &QYWeiXinAPI{}
)

type QYWeiXinAPI struct {
	//
	CorpID string
	//
	AppID     int64
	AppSecret string
	//
	flag uint32
	//
	enabled uint32
	//
	accessToken string
}

func (this *QYWeiXinAPI) Init() {
	//
	if "" != this.CorpID && 0 < this.AppID && "" != this.AppSecret {
		//
		if atomic.CompareAndSwapUint32(&this.flag, 0x0, 0x1) {
			//
			go func() {
				//
				var failcnt int
				//
				result := struct {
					ErrCode     int    `json:"errcode"`
					ErrMsg      string `json:"errmsg"`
					AccessToken string `json:"access_token"`
					ExpiresIn   int64  `json:"expires_in"`
				}{}
				//
				defer atomic.StoreUint32(&this.flag, 0x0)
				//
				for {
					//
					if err := httplib.Get(fmt.Sprintf(
						"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=%s&corpsecret=%s",
						this.CorpID, this.AppSecret,
					)).ToJSON(&result); nil == err {
						//
						if 0 == result.ErrCode && "ok" == result.ErrMsg {
							//
							if "" != result.AccessToken {
								//
								failcnt = 0
								//
								ioutil.WriteFile("/tmp/qq2wechat.txt", []byte(result.AccessToken), 0644)
								//
								this.accessToken = result.AccessToken
								//
								//this.SendText("测试\n测试\n测试\n测试\n测试")
								//
								if 181 > result.ExpiresIn {
									//
									result.ExpiresIn = 181
								}
								//
								time.Sleep(time.Duration(result.ExpiresIn-180) * time.Second)
								//
								continue
							}
						}
					}
					//
					if 5 > failcnt {
						//
						time.Sleep(3 * time.Second)
						//
						failcnt++
					} else {
						//
						time.Sleep(60 * time.Second)
					}
				}
			}()
		}
	}
}

func (this *QYWeiXinAPI) SetEnabled(flag bool) {
	//
	fmt.Println("QYWeiXinAPI: set enabled", flag)
	//
	if flag {
		//
		atomic.StoreUint32(&this.enabled, 0x1)
		//
		return
	}
	//
	atomic.StoreUint32(&this.enabled, 0x0)
}

func (this *QYWeiXinAPI) SendText(content string) bool {
	//
	if 0x0 == atomic.LoadUint32(&this.flag) {
		//
		return false
	}
	//
	if 0x0 == atomic.LoadUint32(&this.enabled) {
		//
		return false
	}
	//
	for i := 0; 10 > i; i++ {
		//
		if "" != this.accessToken {
			//
			if req, err := httplib.Post(fmt.Sprintf(
				"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=%s",
				this.accessToken,
			)).JSONBody(struct {
				ToUser  string      `json:"touser"`
				MsgType string      `json:"msgtype"`
				AgentID int64       `json:"agentid"`
				Text    interface{} `json:"text"`
			}{
				ToUser:  "@all",
				MsgType: "text",
				AgentID: this.AppID,
				Text: struct {
					Content string `json:"content"`
				}{
					Content: content,
				},
			}); nil == err {
				//
				result := struct {
					ErrCode     int    `json:"errcode"`
					ErrMsg      string `json:"errmsg"`
					InvalidUser string `json:"invaliduser"`
				}{}
				//
				if err := req.ToJSON(&result); nil == err {
					//
					if 0 == result.ErrCode && "ok" == result.ErrMsg {
						//
						return true
					} else {
						//
						logs.Warn(result.ErrCode)
					}
				} else {
					//
					logs.Warn(err)
				}
				//
				return false
			} else {
				//
				logs.Warn(err)
			}
		}
		//
		time.Sleep(3 * time.Second)
	}
	//
	fmt.Println("SendText()发送失败")
	//
	return false
}

func (this *QYWeiXinAPI) SendImage(data []byte) bool {
	//
	if 0x0 == atomic.LoadUint32(&this.flag) {
		//
		return false
	}
	//
	if 0x0 == atomic.LoadUint32(&this.enabled) {
		//
		return false
	}
	//
	media_id := ""
	//
	for i := 0; 10 > i; i++ {
		//
		if "" != this.accessToken {
			//
			fmt.Println("[企业微信] 正在发送图片消息")
			//
			if "" == media_id {
				//
				fmt.Println("[企业微信] 开始上传图片")
				//
				if "http://" == string(data[:7]) || "https://" == string(data[:8]) {
					//
					if resp, err := httplib.Get(string(data)).Response(); nil == err {
						//
						if http.StatusOK == resp.StatusCode {
							//
							if data, err := ioutil.ReadAll(resp.Body); nil == err {
								//
								if _media_id, err := this.uploadMedia(data, "image"); nil == err {
									//
									media_id = _media_id
								} else {
									//
									fmt.Println(err)
								}
							} else {
								//
								fmt.Println(err)
							}
						} else {
							//
							ioutil.ReadAll(resp.Body)
						}
						//
						resp.Body.Close()
					} else {
						//
						fmt.Println(err)
					}
				} else {
					//
					if _media_id, err := this.uploadMedia(data, "image"); nil == err {
						//
						media_id = _media_id
					} else {
						//
						fmt.Println(err)
					}
				}
			} else {
				//
				fmt.Println("[企业微信] 资源已上传完毕")
			}
			//
			fmt.Println("[企业微信] 开始发送")
			//
			if "" != media_id {
				//
				if req, err := httplib.Post(fmt.Sprintf(
					"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=%s",
					this.accessToken,
				)).JSONBody(struct {
					ToUser  string      `json:"touser"`
					MsgType string      `json:"msgtype"`
					AgentID int64       `json:"agentid"`
					Image   interface{} `json:"image"`
				}{
					ToUser:  "@all",
					MsgType: "image",
					AgentID: this.AppID,
					Image: struct {
						MediaID string `json:"media_id"`
					}{
						MediaID: media_id,
					},
				}); nil == err {
					//
					result := struct {
						ErrCode int    `json:"errcode"`
						ErrMsg  string `json:"errmsg"`
					}{}
					//
					if err := req.ToJSON(&result); nil == err {
						//
						if 0 == result.ErrCode && "ok" == result.ErrMsg {
							//
							return true
						} else {
							//
							logs.Warn(result.ErrCode)
						}
					} else {
						//
						logs.Warn(err)
					}
					//
					return false
				} else {
					//
					logs.Warn(err)
				}
			} else {
				//
				fmt.Println("[企业微信] 没有资源ID")
			}
		}
		//
		time.Sleep(3 * time.Second)
	}
	//
	fmt.Println("SendImage()发送失败")
	//
	return false
}

func (this *QYWeiXinAPI) uploadMedia(data []byte, media_type string) (string, error) {
	//
	if n := len(data); 5 < n && 2*1024*1024 >= n {
		//
		var b bytes.Buffer
		//
		mw := multipart.NewWriter(&b)
		//
		header := make(textproto.MIMEHeader)
		//
		header.Set(
			"Content-Disposition",
			fmt.Sprintf(
				`form-data; name="media"; filename="media"; filelength: %d`,
				len(data),
			),
		)
		//
		header.Set("Content-Type", "application/octet-stream")
		//
		if w, err := mw.CreatePart(header); nil == err {
			//
			w.Write(data)
		}
		//
		contentType := mw.FormDataContentType()
		//
		mw.Close()
		//
		result := struct {
			ErrCode int    `json:"errcode"`
			ErrMsg  string `json:"errmsg"`
			MediaID string `json:"media_id"`
		}{}
		//
		if err := httplib.Post(
			fmt.Sprintf(
				"https://qyapi.weixin.qq.com/cgi-bin/media/upload?access_token=%s&type=%s",
				this.accessToken,
				media_type,
			),
		).Header(
			"Content-Type",
			contentType,
		).Body(b.Bytes()).ToJSON(&result); nil == err {
			//
			if 0 == result.ErrCode && "ok" == result.ErrMsg {
				//
				return result.MediaID, nil
			} else {
				//
				return "", fmt.Errorf("response: %d, %s", result.ErrCode, result.ErrMsg)
			}
		} else {
			//
			return "", err
		}
	} else {
		//
		return "", fmt.Errorf("data length was not acceptable")
	}
}

func qrcodeLogin(c *client.QQClient) (*client.QRCodeLoginInfo, bool) {
	//
	for {
		//
		if resp, err := c.FetchQRCode(); nil == err {
			//
			reload := false
			//
			qywx.SendImage(resp.ImageData)
			//
			qywx.SendText("二维码已更新，请将图片下载到本地，然后通过手机QQ/TIM扫码登陆")
			//
			fmt.Println("二维码已更新")
			//
			for !reload {
				//
				fmt.Printf("正在查询: %X\n", resp.Sig)
				//
				if _resp, err := c.QueryQRCodeStatus(resp.Sig); nil == err {
					//
					switch _resp.State {
					case client.QRCodeImageFetch, client.QRCodeWaitingForScan, client.QRCodeWaitingForConfirm:
					case client.QRCodeTimeout, client.QRCodeCanceled:
						//
						reload = true
					case client.QRCodeConfirmed:
						//
						return _resp.LoginInfo, true
					}
				} else {
					//
					fmt.Println("QueryQRCodeStatus:", err)
					//
					break
				}
				//
				time.Sleep(time.Second)
			}
		} else {
			//
			fmt.Println("FetchQRCode:", err)
			//
			if errors.Is(err, client.ErrAlreadyOnline) {
				//
				return nil, true
			} else {
				//
				return nil, false
			}
		}
		//
		time.Sleep(time.Second)
	}
}

func initHttplib(rootCA string) {
	//
	var _t *tls.Config
	//
	if "" == rootCA {
		rootCA = exeDir + "/rootCA.bin"
	}
	//
	if info, err := os.Stat(rootCA); nil == err {
		if 0 < info.Size() {
			if data, err := ioutil.ReadFile(rootCA); nil == err {
				pool := x509.NewCertPool()
				if pool.AppendCertsFromPEM(data) {
					_t = &tls.Config{
						RootCAs:            pool,
						InsecureSkipVerify: false,
					}
				}
			}
		}
	}
	// 设置httplib默认参数
	httplib.SetDefaultSetting(httplib.BeegoHTTPSettings{
		ShowDebug:        false,
		UserAgent:        "httplib",
		ConnectTimeout:   5 * time.Second,
		ReadWriteTimeout: 15 * time.Second,
		TLSClientConfig:  _t,
		Transport: &http.Transport{
			MaxIdleConns:          64,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		CheckRedirect: nil,
		EnableCookie:  false,
		Gzip:          false,
		DumpBody:      false,
		Retries:       3,
	})
}

func main() {
	//
	var mutex sync.Mutex
	//
	var tempEnable bool
	var groupEnable bool
	//
	var corpID string
	//
	var appID int64
	//
	var appSecret string
	//
	var ca string
	//
	var cron_exit string
	//
	flag.BoolVar(&tempEnable, "t", false, "是否开启临时消息转发")
	flag.BoolVar(&groupEnable, "g", false, "是否开启群消息转发")
	//
	flag.StringVar(&corpID, "cid", "", "（企业微信）企业ID.")
	flag.Int64Var(&appID, "aid", 0, "（企业微信）应用ID.")
	flag.StringVar(&appSecret, "key", "", "（企业微信）应用密钥.")
	//
	flag.StringVar(&ca, "ca", "", "CA filepath.")
	//
	flag.StringVar(&cron_exit, "c", "", "cron exit value")
	//
	flag.Parse()
	//
	if "" != corpID && 0 < appID && "" != appSecret {
		//
		qywx.CorpID = corpID
		qywx.AppID = appID
		qywx.AppSecret = appSecret
		//
		qywx.Init()
		//
		y, m, d := time.Now().Date()
		//
		if time.Now().Before(time.Date(y, m, d, 22, 0, 0, 0, time.Local)) {
			//
			qywx.SetEnabled(true)
		}
	}
	//
	if "" != ca {
		//
		initHttplib(ca)
	}
	//
	if c := cron.New(
		cron.WithSeconds(),
		cron.WithLocation(time.FixedZone("UTC+8", 8*60*60)),
	); nil != c {
		//
		gCron = c
		//
		c.Start()
		//
		if id, err := c.AddFunc("0 0 22 * * ?", func() {
			//
			qywx.SetEnabled(false)
		}); nil == err {
			//
			fmt.Printf("qywx.SetEnabled(false): next run at %v(0 0 22 * * ?)\n", c.Entry(id).Next)
		} else {
			//
			fmt.Println(err)
		}
		//
		if id, err := c.AddFunc("0 0 8 * * ?", func() {
			//
			qywx.SetEnabled(true)
		}); nil == err {
			//
			fmt.Printf("qywx.SetEnabled(true): next run at %v(0 0 8 * * ?)\n", c.Entry(id).Next)
		} else {
			//
			fmt.Println(err)
		}
		//
		if "" != cron_exit {
			//
			fmt.Println("cron_exit:", cron_exit)
			// 添加定时执行函数
			if id, err := c.AddFunc(cron_exit, func() {
				//
				if p, err := os.FindProcess(os.Getpid()); nil == err {
					//
					p.Signal(syscall.SIGQUIT)
					p.Signal(syscall.SIGTERM)
					//
					time.Sleep(time.Second)
					//
					p.Signal(syscall.SIGKILL)
				}
			}); nil == err {
				//
				fmt.Printf("exit at %v(%s)\n", c.Entry(id).Next, cron_exit)
			} else {
				//
				fmt.Println(err)
			}
		}
	}
	//
	switch {
	default:
		//
		if data, err := ioutil.ReadFile(exeDir + "/device.json"); nil == err {
			//
			if err := client.SystemDeviceInfo.ReadJson(data); nil == err {
				//
				break
			}
		}
		//
		client.GenRandomDevice()
		//
		ioutil.WriteFile(exeDir+"/device.json", client.SystemDeviceInfo.ToJson(), 0644)
	}
	//
	fmt.Println("\n\n\n\n\n\n")
	//
	fmt.Printf("使用协议: %v\n", func() string {
		switch client.SystemDeviceInfo.Protocol {
		case client.IPad:
			return "iPad"
		case client.AndroidPhone:
			return "Android Phone"
		case client.AndroidWatch:
			return "Android Watch"
		case client.MacOS:
			return "MacOS"
		}
		return "未知"
	}())
	//
	cli := client.NewClientEmpty()
	//
	sendFunc := func(from *message.Sender, content string) {
		//
		go qywx.SendText(
			//
			fmt.Sprintf(
				//
				`来自: "%v"的消息:

%s`,
				//
				func() interface{} {
					//
					if "" != from.CardName {
						//
						return from.CardName
					}
					//
					if "" != from.Nickname {
						//
						return from.Nickname
					}
					//
					if info := cli.FindFriend(from.Uin); nil != info {
						//
						if "" != info.Remark {
							//
							return info.Remark
						}
						//
						if "" != info.Nickname {
							//
							return info.Nickname
						}
					}
					//
					return from.Uin
				}(),
				//
				content,
			),
		)
	}
	//
	msgRecv := func(c *client.QQClient, tag string, msg interface {
		ToString() string
	}) {
		//
		mutex.Lock()
		//
		defer mutex.Unlock()
		//
		switch result := msg.(type) {
		case *message.PrivateMessage:
			//
			if "PrivateMessageEvent" == tag {
				//
				fmt.Println("接收到普通消息")
				//
				sendFunc(result.Sender, msg.ToString())
			}
		case *message.TempMessage:
			//
			if "TempMessageEvent" == tag {
				//
				fmt.Println("接收到临时消息")
				//
				if tempEnable {
					//
					sendFunc(result.Sender, msg.ToString())
				}
			}
		case *message.GroupMessage:
			//
			if "GroupMessageEvent" == tag {
				//
				fmt.Println("接收到群消息")
				//
				if groupEnable {
					//
					sendFunc(result.Sender, msg.ToString())
				}
			}
		}
		//
		fmt.Printf("=== %T(%s) ===============================\n", msg, tag)
		//
		fmt.Println(msg.ToString())
		//
		fmt.Println("=====================================================================")
	}
	//
	cli.PrivateMessageEvent.Subscribe(func(c *client.QQClient, msg *message.PrivateMessage) {
		//
		msgRecv(c, "PrivateMessageEvent", msg)
	})
	//
	cli.TempMessageEvent.Subscribe(func(c *client.QQClient, msg *client.TempMessageEvent) {
		//
		msgRecv(c, "TempMessageEvent", msg.Message)
	})
	//
	cli.GroupMessageEvent.Subscribe(func(c *client.QQClient, msg *message.GroupMessage) {
		//
		msgRecv(c, "GroupMessageEvent", msg)
	})
	//
	cli.SelfPrivateMessageEvent.Subscribe(func(c *client.QQClient, msg *message.PrivateMessage) {
		//
		msgRecv(c, "SelfPrivateMessageEvent", msg)
	})
	//
	cli.SelfGroupMessageEvent.Subscribe(func(c *client.QQClient, msg *message.GroupMessage) {
		//
		msgRecv(c, "SelfGroupMessageEvent", msg)
	})
	//
	startLogin := func() bool {
		//
		if data, err := ioutil.ReadFile(exeDir + "/token.dat"); nil == err {
			//
			fmt.Println("加载登陆令牌")
			//
			for i := 0; 10 > i; i++ {
				//
				fmt.Println("正在使用令牌登陆")
				//
				if err := cli.TokenLogin(data); nil == err {
					//
					fmt.Println("已使用令牌登陆")
					//
					return true
				} else {
					//
					fmt.Println("TokenLogin:", err)
				}
				//
				time.Sleep(3 * time.Second)
			}
			//
			os.Remove(exeDir + "/token.dat")
		}
		//
		fmt.Println("正在使用二维码登陆")
		//
		if info, login_ok := qrcodeLogin(cli); login_ok {
			//
			if nil != info {
				//
				if resp, err := cli.QRCodeLogin(info); nil == err {
					//
					if resp.Success {
						//
						if data := cli.GenToken(); 0 < len(data) {
							//
							ioutil.WriteFile(exeDir+"/token.dat", data, 0644)
						}
						//
						return true
					}
				}
			}
		} else {
			//
			fmt.Println("加载失败，15秒后退出")
			//
			time.Sleep(15 * time.Second)
		}
		//
		return false
	}
	//
	if !startLogin() {
		//
		fmt.Println("无法登陆，退出")
		//
		return
	}
	//
	go func() {
		//
		for {
			//
			mutex.Lock()
			//
			if err := cli.ReloadFriendList(); nil != err {
				//
				fmt.Println(err)
			}
			//
			if err := cli.ReloadGroupList(); nil != err {
				//
				fmt.Println(err)
			}
			//
			fmt.Println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
			fmt.Println("Uin:", cli.Uin)
			//fmt.Printf("PasswordMd5: %X\n", cli.PasswordMd5[:])
			fmt.Println("AllowSlider:", cli.AllowSlider)
			fmt.Println("Nickname:", cli.Nickname)
			fmt.Println("Age:", cli.Age)
			fmt.Println("Gender:", cli.Gender)
			fmt.Println("Online:", cli.Online)
			fmt.Println("Friend:", len(cli.FriendList))
			fmt.Println("Group:", len(cli.GroupList))
			fmt.Println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
			//
			if list, err := cli.GetAllowedClients(); nil == err {
				//
				fmt.Println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
				//
				for _, item := range list {
					//
					fmt.Println(item.AppId, item.DeviceName, item.DeviceKind)
				}
				//
				fmt.Println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
			}
			//
			mutex.Unlock()
			//
			time.Sleep(5 * time.Minute)
		}
	}()
	//
	select {}
}
