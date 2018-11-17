// 错误定义

package apiproxy

import (
	"git.quyun.com/apibox/api"
)

// error type
const (
	errorGatewayFailed = iota
	errorGatewayResultUnrecognized
	errorSessionNotReady
)

var ErrorDefines = map[api.ErrorType]*api.ErrorDefine{
	errorGatewayFailed: api.NewErrorDefine(
		"GatewayFailed",
		[]int{0},
		map[string]map[int]string{
			"en_us": {
				0: "Gateway request failed!",
			},
			"zh_cn": {
				0: "请求网关失败！",
			},
		},
	),
	errorGatewayResultUnrecognized: api.NewErrorDefine(
		"GatewayResultUnrecognized",
		[]int{0},
		map[string]map[int]string{
			"en_us": {
				0: "Gateway result unrecognized!",
			},
			"zh_cn": {
				0: "网关返回结果不可识别！",
			},
		},
	),
	errorSessionNotReady: api.NewErrorDefine(
		"SessionNotReady",
		[]int{0},
		map[string]map[int]string{
			"en_us": {
				0: "Session is not ready!",
			},
			"zh_cn": {
				0: "会话未准备好！",
			},
		},
	),
}
