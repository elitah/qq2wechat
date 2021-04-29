# qq2wechat
forward tencent qq message to wechat

##### 中文说明
这个项目是偶然看到[MiraiGo](https://github.com/Mrs4s/MiraiGo)提供的非常丰富的接口，花了半天随手写几行代码，分享给需要的人

有需要可以自己增加新功能（本人懒，不打算再完善了）

使用这个项目的必要条件：
- 手机安装企业微信（个人可免费注册）
- 手机安装QQ或TIM
- Golang编译环境（至少1.13）

##### 使用步骤
1. 登陆到企业微信后台，[点此直达](https://work.weixin.qq.com/wework_admin/loginpage_wx?from=myhome)
2. 获取企业ID，打开我的企业，然后下拉到底部，[点此直达](https://work.weixin.qq.com/wework_admin/frame#profile)
3. 创建一个应用，[步骤](https://open.work.weixin.qq.com/api/doc/90000/90003/90487#%E6%B7%BB%E5%8A%A0%E8%87%AA%E5%BB%BA%E5%BA%94%E7%94%A8)
4. 获取应用AgentId和Secret，Secret需要使用企业微信APP来接收，请提前在手机上安装好
5. 已成功获取企业ID、应用AgentId、应用Secret这个值以后，开始编译
6. 执行go build -ldflags "-w -s"
7. 执行./qq2wechat -cid "此处填企业ID" -aid "此处填应用AgentId" -key "此处填应用Secret"
8. OK
