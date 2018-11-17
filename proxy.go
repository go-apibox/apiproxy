package apiproxy

import (
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"

	"git.quyun.com/apibox/api"
	"git.quyun.com/apibox/apiclient"
	"git.quyun.com/apibox/session"
	"git.quyun.com/apibox/utils"
	"github.com/gorilla/websocket"
)

type Proxy struct {
	app      *api.App
	disabled bool
	inited   bool

	trustedRproxyIpMap map[string]bool // 受信任的反向代理IP

	conds        map[string]map[string][]string // map[参数名]map[参数值]后端API名称数组
	backends     map[string]*apiclient.Client
	condCount    map[string]int
	methods      map[string]string
	deleteParams map[string][]string
	proxyCookies map[string][]string
	proxyHeaders map[string][]string

	sessionStore  *session.CookieStore
	sessionParams map[string]map[string]string

	mutex sync.RWMutex
}

func NewProxy(app *api.App) *Proxy {
	app.Error.RegisterGroupErrors("proxy", ErrorDefines)

	proxy := new(Proxy)
	proxy.app = app
	proxy.trustedRproxyIpMap = make(map[string]bool)
	proxy.conds = make(map[string]map[string][]string)
	proxy.backends = make(map[string]*apiclient.Client)
	proxy.condCount = make(map[string]int)
	proxy.methods = make(map[string]string)
	proxy.deleteParams = make(map[string][]string)
	proxy.sessionParams = make(map[string]map[string]string)
	proxy.proxyCookies = make(map[string][]string)
	proxy.proxyHeaders = make(map[string][]string)
	proxy.mutex = sync.RWMutex{}

	cfg := app.Config
	disabled := cfg.GetDefaultBool("apiproxy.disabled", false)
	proxy.disabled = disabled
	if disabled {
		return proxy
	}

	proxy.init()
	return proxy
}

func (p *Proxy) init() {
	if p.inited {
		return
	}

	app := p.app
	cfg := app.Config

	trustedIps := cfg.GetDefaultStringArray("trusted_rproxy_ips", []string{})
	for _, ip := range trustedIps {
		p.trustedRproxyIpMap[ip] = true
	}

	backendAliases, err := cfg.GetSubKeys("apiproxy.backends")
	if err != nil {
		p.inited = true
		return
	}

	conds := p.conds
	backends := p.backends
	condCount := p.condCount
	methods := p.methods
	deleteParams := p.deleteParams
	sessionParams := p.sessionParams
	proxyCookies := p.proxyCookies
	proxyHeaders := p.proxyHeaders

	for _, alias := range backendAliases {
		aliasPrefix := "apiproxy.backends." + alias
		gwUrl := cfg.GetDefaultString(aliasPrefix+".gwurl", "")
		if gwUrl == "" {
			continue
		}
		c := apiclient.NewClient(gwUrl)
		gwAddr := cfg.GetDefaultString(aliasPrefix+".gwaddr", "")
		if gwAddr != "" {
			c.GWADDR = gwAddr
		}
		appId := cfg.GetDefaultString(aliasPrefix+".app_id", "")
		if appId != "" {
			c.AppId = appId
		}
		signKey := cfg.GetDefaultString(aliasPrefix+".sign_key", "")
		if signKey != "" {
			c.SignKey = signKey
		}
		nonceLength := cfg.GetDefaultInt(aliasPrefix+".nonce_length", 0)
		if nonceLength > 0 {
			c.NonceEnabled = true
			c.NonceLength = nonceLength
		}
		defaultParams, err := cfg.GetSubKeys(aliasPrefix + ".default_params")
		if err == nil {
			pPrefix := aliasPrefix + ".default_params"
			for _, p := range defaultParams {
				v := cfg.GetDefaultString(pPrefix+"."+p, "")
				c.SetDefaultParam(p, v)
			}
		}
		sParams := make(map[string]string)
		overrideParams, err := cfg.GetSubKeys(aliasPrefix + ".override_params")
		if err == nil {
			pPrefix := aliasPrefix + ".override_params"
			for _, p := range overrideParams {
				v := cfg.GetDefaultString(pPrefix+"."+p, "")
				if v[0] == '@' {
					sParams[p] = v[1:]
				} else {
					c.SetOverrideParam(p, v)
				}
			}
		}
		matchParamCount := 0
		matchParams, err := cfg.GetSubKeys(aliasPrefix + ".match_params")
		if err == nil {
			pPrefix := aliasPrefix + ".match_params"
			for _, p := range matchParams {
				matches := cfg.GetDefaultStringArray(pPrefix+"."+p, []string{})
				if len(matches) > 0 {
					matchParamCount++
					if conds[p] == nil {
						conds[p] = make(map[string][]string)
					}
					for _, matchV := range matches {
						conds[p][matchV] = append(conds[p][matchV], alias)
					}
				}
			}
		}

		backends[alias] = c
		condCount[alias] = matchParamCount
		proxyCookies[alias] = cfg.GetDefaultStringArray(aliasPrefix+".proxy_cookies", []string{})
		proxyHeaders[alias] = cfg.GetDefaultStringArray(aliasPrefix+".proxy_headers", []string{})

		method := cfg.GetDefaultString(aliasPrefix+".method", "")
		method = strings.ToUpper(method)
		if method != "GET" && method != "POST" {
			method = ""
		}
		methods[alias] = method

		deleteParams[alias] = cfg.GetDefaultStringArray(aliasPrefix+".delete_params", []string{})
		if len(sParams) > 0 {
			sessionParams[alias] = sParams
		}
	}

	if len(sessionParams) > 0 {
		p.sessionStore, _ = app.SessionStore()
	}
	p.inited = true
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if p.disabled {
		next(w, r)
		return
	}

	c, err := api.NewContext(p.app, w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	p.mutex.RLock()

	// 计算各后端API系统的参数匹配次数
	condMatchCount := make(map[string]int)
	for paramName, matchMap := range p.conds {
		paramVal := c.Input.Get(paramName)

		// 全等匹配
		backendAliases, ok := matchMap[paramVal]
		if ok {
			for _, alias := range backendAliases {
				condMatchCount[alias] = condMatchCount[alias] + 1
			}
		}

		if paramVal == "" {
			continue
		}
		// 匹配*
		for pattern, _ := range matchMap {
			if strings.IndexByte(pattern, '*') < 0 {
				continue
			}
			matched, _ := filepath.Match(pattern, paramVal)
			if matched {
				backendAliases := matchMap[pattern]
				for _, alias := range backendAliases {
					condMatchCount[alias] = condMatchCount[alias] + 1
				}
			}
		}
	}

	var matchAlias string
	var maxMatchCount int

	// 找出匹配的后端，如果多个后端匹配，取匹配条件数最多的
	for alias, count := range condMatchCount {
		if p.condCount[alias] == count {
			// 满足条件，但为本地调用，则不代理
			if p.backends[alias].GWURL == "@" {
				p.mutex.RUnlock()
				next(w, r)
				return
			}

			// 满足条件，则将请求代理到该后端API
			if count > maxMatchCount {
				maxMatchCount = count
				matchAlias = alias
			}

		}
	}

	p.mutex.RUnlock()

	if matchAlias != "" {
		p.proxyCall(c, matchAlias)
		return
	}

	// next middleware
	next(w, r)
}

func (p *Proxy) proxyCall(c *api.Context, backendAlias string) {
	action := c.Input.GetAction()
	params := make(url.Values)
	for k, v := range c.Input.GetForm() {
		params[k] = v
	}
	resp, apiErr := p.ProxyCall(c, backendAlias, action, params)
	if apiErr != nil {
		// 如果是websocket，则不返回任何数据，否则会报错：
		// http: response.WriteHeader on hijacked connection
		// http: response.Write on hijacked connection
		if strings.ToLower(c.Request().Header.Get("Upgrade")) != "websocket" {
			api.WriteResponse(c, apiErr)
		}
		return
	}
	defer resp.Body.Close()

	isOk := true
	if resp.StatusCode != http.StatusOK {
		isOk = false
	}

	// var result *api.Result
	respHeader := c.Response().Header()

	// 带上Content-Type
	contentType := resp.Header.Get("Content-Type")
	if contentType != "" {
		respHeader.Set("Content-Type", contentType)
	}
	// 带上Content-Disposition
	contentDisposition := resp.Header.Get("Content-Disposition")
	if contentDisposition != "" {
		respHeader.Set("Content-Disposition", contentDisposition)
	}
	// 带上X-Request-Id
	reqId := resp.Header.Get("X-Request-Id")
	if reqId != "" {
		respHeader.Set("X-Request-Id", reqId)
	}
	// 带上X-Allow-Error-Response
	allowErrorResponse := resp.Header.Get("X-Allow-Error-Response")
	if allowErrorResponse != "" {
		respHeader.Set("X-Allow-Error-Response", allowErrorResponse)
	}

	if isOk {
		contentType := resp.Header.Get("Content-Type")
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err == nil && mediaType != "application/json" && mediaType != "application/javascript" {
			// 下载
			// 带上Cache-Control
			cacheControl := resp.Header.Get("Cache-Control")
			if cacheControl != "" {
				respHeader.Set("Cache-Control", cacheControl)
			}
			// 带上Last-Modified
			lastModifed := resp.Header.Get("Last-Modified")
			if lastModifed != "" {
				respHeader.Set("Last-Modified", lastModifed)
			}
			// 带上Etag
			etag := resp.Header.Get("Etag")
			if etag != "" {
				respHeader.Set("Etag", etag)
			}

			rw := c.Response()
			_, err := io.Copy(rw, resp.Body)
			if err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}

		// result, err = resp.Result()
		// if err != nil {
		//  // c.App.Logger.Error("%s",err.Error())
		// 	// api.WriteResponse(c, c.Error.NewGroupError("proxy", errorGatewayResultUnrecognized)
		// 	// return

		// 	// 直接返回原文
		// 	rw := c.Response()
		// 	_, err := io.Copy(rw, resp.Body)
		// 	if err != nil {
		// 		http.Error(rw, err.Error(), http.StatusInternalServerError)
		// 		return
		// 	}
		// 	return
		// }
	} else {
		// 如果是websocket，则不返回任何数据，否则会报错：
		// http: response.WriteHeader on hijacked connection
		// http: response.Write on hijacked connection
		if strings.ToLower(c.Request().Header.Get("Upgrade")) != "websocket" {
			c.Response().WriteHeader(resp.StatusCode)
		}
		return
	}

	// 返回请求结果头部的cookie
	if proxyCookies := p.proxyCookies[backendAlias]; len(proxyCookies) > 0 {
		respHeader := c.Response().Header()
		cookies := resp.Cookies()
		for _, cookie := range cookies {
			needProxy := false
			for _, proxyCookie := range proxyCookies {
				if proxyCookie == cookie.Name {
					needProxy = true
					break
				}
			}
			if needProxy {
				respHeader.Add("Set-Cookie", cookie.String())
			}
		}
	}

	// 返回其它响应头
	if proxyHeaders := p.proxyHeaders[backendAlias]; len(proxyHeaders) > 0 {
		for _, proxyHeader := range proxyHeaders {
			if val := resp.Header.Get(proxyHeader); val != "" {
				respHeader.Set(proxyHeader, val)
			}
		}
	}

	// if isOk {
	// 	if result.CODE == "ok" {
	// 		api.WriteResponse(c, result.DATA)
	// 	} else {
	// 		api.WriteResponse(c, api.NewError(result.CODE, result.MESSAGE).SetData(result.DATA))
	// 	}
	// } else {
	// 直接返回原文
	rw := c.Response()
	_, err := io.Copy(rw, resp.Body)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
	// }
}

func (p *Proxy) ProxyCall(c *api.Context, backendAlias string, action string, params url.Values) (*apiclient.Response, *api.Error) {
	w := c.Response()
	r := c.Request()
	client := p.backends[backendAlias].Clone() // clone一个新的client，防止污染
	method := p.methods[backendAlias]
	if method == "" {
		method = r.Method
	}
	sParams, ok := p.sessionParams[backendAlias]
	if !ok {
		sParams = make(map[string]string)
	}

	// 自动继承部分全局参数值
	inheritedKeys := []string{"api_lang", "api_debug"}
	for _, key := range inheritedKeys {
		if params.Get(key) == "" {
			val := c.Input.Get(key)
			if val != "" {
				params.Set(key, val)
			}
		}
	}

	for _, v := range p.deleteParams[backendAlias] {
		params.Del(v)
	}

	// 处理override_params中的session变量
	if len(sParams) > 0 {
		if p.sessionStore == nil {
			return nil, c.Error.NewGroupError("proxy", errorSessionNotReady)
		}
		for k, v := range sParams {
			parts := strings.SplitN(v, ".", 2)
			if len(parts) == 2 {
				sessionName := parts[0]
				keyName := parts[1]
				s, err := p.sessionStore.Get(r, sessionName)
				if err == nil {
					if sessionVal, ok := s.Values[keyName]; ok {
						if sessionVal != nil {
							client.SetOverrideParam(k, fmt.Sprint(sessionVal))
						}
					}
				}
			}
		}
	}

	header := make(http.Header)
	var remoteIp string
	if r.RemoteAddr != "@" {
		remoteIp, _, _ = net.SplitHostPort(r.RemoteAddr)
	} else {
		// unix domain socket
		remoteIp = "@"
	}

	isTrustIp := false
	if remoteIp == "@" || utils.IsPrivateIp(remoteIp) {
		isTrustIp = true
	} else if _, has := p.trustedRproxyIpMap[remoteIp]; has {
		isTrustIp = true
	}
	if isTrustIp {
		realIp := r.Header.Get("X-Real-IP")
		if realIp != "" && realIp != "@" {
			remoteIp = realIp
		}
	}

	header.Set("X-Real-IP", remoteIp)

	// 带上请求头部的cookie
	if proxyCookies := p.proxyCookies[backendAlias]; len(proxyCookies) > 0 {
		for _, cookie := range r.Cookies() {
			needProxy := false
			for _, proxyCookie := range proxyCookies {
				if proxyCookie == cookie.Name {
					needProxy = true
					break
				}
			}
			if needProxy {
				header.Add("Cookie", cookie.String())
			}
		}
	}

	// 带上Content-Type
	contentType := r.Header.Get("Content-Type")
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}

	// 带上其它请求头
	if proxyHeaders := p.proxyHeaders[backendAlias]; len(proxyHeaders) > 0 {
		for _, proxyHeader := range proxyHeaders {
			if val := r.Header.Get(proxyHeader); val != "" {
				header.Set(proxyHeader, val)
			}
		}
	}

	// 判断是否websocket请求
	if strings.ToLower(r.Header.Get("Upgrade")) != "websocket" {
		var resp *apiclient.Response
		var err error

		switch method {
		case "GET":
			resp, err = client.Get(action, params, header)
		case "POST":
			// 判断是否上传文件
			isMultiPart := false
			if contentType != "" {
				mediaType, _, err := mime.ParseMediaType(contentType)
				if err == nil && strings.HasPrefix(mediaType, "multipart/") {
					isMultiPart = true
				}
			}

			if !isMultiPart {
				resp, err = client.Post(action, params, header)
			} else {
				resp, err = client.Upload(action, params, header, r.Body)
			}
		default:
			return nil, c.Error.New(api.ErrorInternalError, "BadRequestMethod")
		}

		if err != nil {
			if resp != nil && resp.Header.Get("X-Allow-Error-Response") == "on" {
				// 返回原始响应内容
				return resp, nil
			}
			c.App.Logger.Error("%s", err.Error())
			return nil, c.Error.NewGroupError("proxy", errorGatewayFailed)
		}

		return resp, nil
	} else {
		// websocket
		resp, err := client.Websocket(action, params, header, w, r)
		if err != nil {
			// 非关闭连接错误，均打印日志，连接错误示例：
			// websocket: close 1006 unexpected EO
			err = ignoreCloseError(err)
			if err != nil {
				c.App.Logger.Error("%s", err.Error())
			}
			return nil, c.Error.NewGroupError("proxy", errorGatewayFailed)
		}
		return resp, nil
	}
}

// 忽略关闭连接的错误
func ignoreCloseError(err error) error {
	if err == nil {
		return nil
	}

	// websocket failed: websocket: close 1005
	if _, ok := err.(*websocket.CloseError); ok {
		return nil
	}

	errStr := err.Error()
	if strings.Contains(errStr, "use of closed network connection") {
		// go库net/net.go中获取到的网络错误，如：
		// websocket failed: read tcp 192.168.1.140:8888->192.168.1.52:51058: use of closed network connection
		return nil
	}
	if strings.Contains(errStr, "broken pipe") {
		// write unix /opt/appnode/agent/run/bus.sock->@: write: broken pipe
		return nil
	}
	if strings.Contains(errStr, "unexpected EOF") {
		// websocket: close 1006 unexpected EOF
		return nil
	}

	return err
}

// GetClient return the backend client object.
func (p *Proxy) GetClient(alias string) *apiclient.Client {
	if c, ok := p.backends[alias]; ok {
		return c
	}
	return nil
}

// SetClient set the backend client object.
func (p *Proxy) SetClient(alias string, client *apiclient.Client) {
	if _, ok := p.backends[alias]; ok {
		p.backends[alias] = client
	}
}

type Backend struct {
	GWURL            string
	GWADDR           string
	Method           string
	AppId            string
	SignKey          string
	NonceLength      int
	DefaultParams    map[string]string
	OverrideParams   map[string]string
	DeleteParams     []string
	MatchParams      map[string][]string
	SSHTunnelEnabled bool
	SSHClient        *apiclient.SSHClient
}

// AddBackend add a new backend to proxy.
func (p *Proxy) AddBackend(alias string, backend *Backend) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if _, has := p.backends[alias]; has {
		return
	}

	if backend.GWURL == "" {
		return
	}
	c := apiclient.NewClient(backend.GWURL)
	if backend.GWADDR != "" {
		c.GWADDR = backend.GWADDR
	}
	if backend.AppId != "" {
		c.AppId = backend.AppId
	}
	if backend.SignKey != "" {
		c.SignKey = backend.SignKey
	}
	if backend.NonceLength > 0 {
		c.NonceEnabled = true
		c.NonceLength = backend.NonceLength
	}
	for p, v := range backend.DefaultParams {
		c.SetDefaultParam(p, v)
	}
	sParams := make(map[string]string)
	for p, v := range backend.OverrideParams {
		if v[0] == '@' {
			sParams[p] = v[1:]
		} else {
			c.SetOverrideParam(p, v)
		}
	}
	c.SSHTunnelEnabled = backend.SSHTunnelEnabled
	c.SSHClient = backend.SSHClient
	matchParamCount := 0
	conds := p.conds
	for paramName, matches := range backend.MatchParams {
		if len(matches) > 0 {
			matchParamCount++
			if conds[paramName] == nil {
				conds[paramName] = make(map[string][]string)
			}
			for _, matchV := range matches {
				conds[paramName][matchV] = append(conds[paramName][matchV], alias)
			}
		}
	}

	p.backends[alias] = c
	p.condCount[alias] = matchParamCount

	method := strings.ToUpper(backend.Method)
	if method != "GET" && method != "POST" {
		method = ""
	}
	p.methods[alias] = method
	p.deleteParams[alias] = backend.DeleteParams
	if len(sParams) > 0 {
		p.sessionParams[alias] = sParams
	}

	if len(p.sessionParams) > 0 {
		p.sessionStore, _ = p.app.SessionStore()
	}
}

// DeleteBackend delete a backend from proxy.
func (p *Proxy) DeleteBackend(alias string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if _, has := p.backends[alias]; !has {
		return
	}

	found := false
	for k, v := range p.conds {
		for kk, vv := range v {
			for i, vvv := range vv {
				if vvv == alias {
					p.conds[k][kk] = append(vv[:i], vv[i+1:]...)
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if found {
			break
		}
	}
	delete(p.backends, alias)
	delete(p.condCount, alias)
	delete(p.methods, alias)
	delete(p.deleteParams, alias)
	delete(p.sessionParams, alias)
}

// Enable enable the middle ware.
func (p *Proxy) Enable() {
	p.disabled = false
	p.init()
}

// Disable disable the middle ware.
func (p *Proxy) Disable() {
	p.disabled = true
}
