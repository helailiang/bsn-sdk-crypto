package pki

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/BSNDA/bsn-sdk-crypto/pkg/curl"
)

// PKI服务配置
const (
	DefaultPKIServiceURL = "http://10.0.6.65:8080" // 默认PKI服务地址
	DefaultTimeout       = 30                      // 默认超时时间（秒）
)

// 证书生成请求结构
type CertificateRequest struct {
	Header CertificateHeader `json:"header"`
	Body   CertificateBody   `json:"body"`
}

// 请求头
type CertificateHeader struct {
	RequestID   string `json:"requestId"`
	Timestamp   string `json:"timestamp"`
	Version     string `json:"version"`
	ServiceType string `json:"serviceType"`
}

// 请求体
type CertificateBody struct {
	CertificateType string                `json:"certificateType"` // 证书类型：orderer, org, peer
	OrgName         string                `json:"orgName"`         // 组织名称
	NodeName        string                `json:"nodeName"`        // 节点名称（可选）
	Consortium      string                `json:"consortium"`      // 联盟名称
	Domain          string                `json:"domain"`          // 域名
	ValidityDays    int                   `json:"validityDays"`    // 有效期（天）
	KeyAlgorithm    string                `json:"keyAlgorithm"`    // 密钥算法：RSA, ECDSA
	KeySize         int                   `json:"keySize"`         // 密钥长度
	Subject         CertificateSubject    `json:"subject"`         // 证书主题
	Extensions      CertificateExtensions `json:"extensions"`      // 证书扩展
}

// 证书主题
type CertificateSubject struct {
	Country            string `json:"country"`
	State              string `json:"state"`
	Locality           string `json:"locality"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizationalUnit"`
	CommonName         string `json:"commonName"`
}

// 证书扩展
type CertificateExtensions struct {
	KeyUsage       []string `json:"keyUsage"`
	ExtKeyUsage    []string `json:"extKeyUsage"`
	SubjectAltName []string `json:"subjectAltName"`
}

// 证书生成响应结构
type CertificateResponse struct {
	Header ResponseHeader `json:"header"`
	Body   ResponseBody   `json:"body"`
}

// 响应头
type ResponseHeader struct {
	RequestID     string `json:"requestId"`
	Timestamp     string `json:"timestamp"`
	Version       string `json:"version"`
	StatusCode    int    `json:"statusCode"`
	StatusMessage string `json:"statusMessage"`
}

// 响应体
type ResponseBody struct {
	CertificateID string `json:"certificateId"`
	Certificate   string `json:"certificate"` // Base64编码的证书
	PrivateKey    string `json:"privateKey"`  // Base64编码的私钥
	PublicKey     string `json:"publicKey"`   // Base64编码的公钥
	ExpiryDate    string `json:"expiryDate"`  // 过期时间
}

// PKI服务客户端
type PKIClient struct {
	ServiceURL string
}

// 创建PKI客户端
func NewPKIClient(serviceURL string) *PKIClient {
	if serviceURL == "" {
		serviceURL = DefaultPKIServiceURL
	}
	return &PKIClient{
		ServiceURL: serviceURL,
	}
}

// 生成证书
func (c *PKIClient) GenerateCertificate(req *CertificateRequest) (*CertificateResponse, error) {
	url := fmt.Sprintf("%s/api/v1/certificates/generate", c.ServiceURL)

	// 发送请求
	response, err := curl.Post(url, req, curl.ApplicationJSON)
	if err != nil {
		log.Printf("PKI服务请求失败: %v", err)
		return nil, fmt.Errorf("PKI service request failed: %v", err)
	}

	// 解析响应
	var certResponse CertificateResponse
	err = json.Unmarshal([]byte(response), &certResponse)
	if err != nil {
		log.Printf("解析PKI服务响应失败: %v", err)
		return nil, fmt.Errorf("failed to parse PKI service response: %v", err)
	}

	// 检查响应状态
	if certResponse.Header.StatusCode != 200 {
		return nil, fmt.Errorf("PKI service error: %s", certResponse.Header.StatusMessage)
	}

	return &certResponse, nil
}

// 生成请求ID
func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

// 获取当前时间戳
func getCurrentTimestamp() string {
	return fmt.Sprintf("%d", time.Now().Unix())
}

// 链证书创建请求结构（根据PKI文档规范）
type ChainCertificateRequest struct {
	Header ChainCertificateHeader `json:"header"`
	Body   ChainCertificateBody   `json:"body"`
}

// 链证书请求头
type ChainCertificateHeader struct {
	Timestamp string `json:"timestamp"`
	Mac       string `json:"mac"`
}

// 链证书请求体（根据PKI文档规范）
type ChainCertificateBody struct {
	Issuer         string     `json:"issuer"`         // 颁发者用户
	IssuerPwd      string     `json:"issuerPwd"`      // 颁发者账户密码
	IssuerCertName string     `json:"issuerCertName"` // 颁发者证书名称
	CertSysCode    string     `json:"certSysCode"`    // 证书体系编号
	FrameCode      string     `json:"frameCode"`      // 框架编号
	KeyAlgo        int        `json:"keyAlgo"`        // 密钥算法
	Expiry         int        `json:"expiry"`         // 证书有效时间（年）
	NetCode        string     `json:"netCode"`        // 网络编号
	Provider       string     `json:"provider"`       // 提供商
	CsrName        *CsrName   `json:"csrName"`        // 自签证书CSR数据
	CertBelongOut  bool       `json:"certBelongOut"`  // 证书归属外部
	NodeInfo       []NodeInfo `json:"nodeInfo"`       // 节点信息
}

// CSR名称结构
type CsrName struct {
	CN string `json:"CN"`
	C  string `json:"C"`  // 国家
	ST string `json:"ST"` // 省（州）
	L  string `json:"L"`  // 地区
	O  string `json:"O"`  // 组织
	OU string `json:"OU"` // 组织单元
}

// 节点信息结构
type NodeInfo struct {
	OrgName       string `json:"orgName"`       // 组织名称
	NodeCount     int    `json:"nodeCount"`     // 节点数量
	NodeType      int    `json:"nodeType"`      // 节点类型：1: 共识节点，2: 记账节点
	Namespace     string `json:"namespace"`     // 命名空间
	Domain        string `json:"domain"`        // 域名
	InitialNumber int    `json:"initialNumber"` // 起始节点数
}

// 链证书创建响应结构（根据PKI文档规范）
type ChainCertificateResponse struct {
	Header ResponseHeader    `json:"header"`
	Body   ChainResponseBody `json:"body"`
}

// 链证书响应体
type ChainResponseBody struct {
	Code int               `json:"code"`
	Data ChainResponseData `json:"data"`
	Msg  string            `json:"msg"`
}

// 链证书响应数据
type ChainResponseData struct {
	CertSysCode       string      `json:"certSysCode"`       // 证书体系编号
	UrlPath           string      `json:"urlPath"`           // 证书下载地址
	FileBase64Content string      `json:"fileBase64Content"` // 证书内容base64形式
	Certs             []IssueUser `json:"certs"`             // 证书列表
}

// 证书用户信息
type IssueUser struct {
	CertCode     string `json:"certCode"`     // 证书名称
	CertAki      string `json:"certAki"`      // AKI
	CertSki      string `json:"certSki"`      // SKI
	SerialNumber string `json:"serialNumber"` // 序列号
	CertType     int    `json:"certType"`     // 证书类型
	CertUsage    int    `json:"certUsage"`    // 证书用途
	PkiType      int    `json:"pkiType"`      // PKI类型 1：密钥 2：证书
	GroupType    int    `json:"groupType"`    // 分组类型
	GroupCode    string `json:"groupCode"`    // 分组名称
	IssuerCode   string `json:"issuerCode"`   // 颁发者证书编号
	KeyId        string `json:"keyId"`        //密钥的唯一标识
	Status       int    `json:"status"`
}

type NodeKeyGenerateReq struct {
	Header *NodeKeyGenerateHeader  `json:"header"`
	Body   *NodeKeyGenerateReqBody `json:"body"`
}

type NodeKeyGenerateHeader struct {
	Timestamp string `json:"timestamp"`
	Mac       string `json:"mac"`
}

type NodeKeyGenerateReqBody struct {
	KeyAlgo       int    `json:"keyAlgo"`
	NodeCount     int    `json:"nodeCount"`
	NetCode       string `json:"netCode"`
	Origin        string `json:"origin"`
	OrgName       string `json:"orgName"`
	NodeType      int    `json:"nodeType"`
	Provider      string `json:"provider"`
	AlgorithmType int    `json:"algorithmType"`
}

type NodeKey struct {
	PrivateKey          string `json:"privateKey"`          // 节点私钥
	PublicKey           string `json:"publicKey"`           // 节点公钥
	Address             string `json:"address"`             // 节点地址
	KeyStore            string `json:"keyStore"`            // 密钥存储信息
	KeyAlgo             int    `json:"keyAlgo"`             // 密钥算法
	KeyCode             string `json:"keyCode"`             // 密钥代码
	ClearTextPrivateKey string `json:"clearTextPricateKey"` // 私钥明文
	KeyId               string `json:"keyId"`               // 密钥ID
}

type NodeKeyGenerateData struct {
	NodeKey []NodeKey `json:"nodeKey"`
}

type NodeKeyGenerateResBody struct {
	Code int                 `json:"code"` // 响应代码，0表示成功
	Data NodeKeyGenerateData `json:"data"` // 响应数据
	Msg  string              `json:"msg"`  // 响应消息
}

type NodeKeyGenerateRes struct {
	Header *NodeKeyGenerateHeader  `json:"header"`
	Body   *NodeKeyGenerateResBody `json:"body"`
}

func (c *PKIClient) NodeKeyGenerate(req *NodeKeyGenerateReq) (*NodeKeyGenerateRes, error) {
	url := fmt.Sprintf("%s/api/v1/ca/nodekey/generate", c.ServiceURL)
	result, err := curl.Post(url, req, curl.ApplicationJSON)
	if err != nil {
		return nil, err
	}
	var res *NodeKeyGenerateRes
	err = json.Unmarshal([]byte(result), &res)
	if err != nil {
		return nil, err
	}
	if res.Body.Code != 0 {
		return nil, fmt.Errorf("请求失败，状态码: %d, 响应: %s", res.Body.Code, res.Body.Msg)
	}
	return res, nil
}

type Header struct {
	Timestamp string `json:"timestamp"`
	Mac       string `json:"mac"`
}
type SignReqBody struct {
	KeyId       string `json:"keyId"`
	SignAlgo    string `json:"signAlgo"`
	Input       string `json:"input"` //定义要签名的消息或消息摘要,Base64 编码
	Provider    string `json:"provider"`
	MessageType string `json:"messageType"` // - DIGEST 表示消息摘要 - RAW 表示消息原文
}

type SignReq struct {
	Header *Header      `json:"header"`
	Body   *SignReqBody `json:"body"`
}

type SignResData struct {
	Signature string `json:"signature"` // 使用base64编码。
}
type SignResBody struct {
	Code int         `json:"code"` // 响应代码，0表示成功
	Data SignResData `json:"data"` // 响应数据
	Msg  string      `json:"msg"`  // 响应消息
}

type SignRes struct {
	Header *Header      `json:"header"`
	Body   *SignResBody `json:"body"`
}

func (c *PKIClient) Sign(reqBody *SignReqBody) (*SignResBody, error) {
	req := &SignReq{
		Header: &Header{
			Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		},
		Body: reqBody,
	}
	url := fmt.Sprintf("%s/api/v1/kms/sign", c.ServiceURL)
	result, err := curl.Post(url, req, curl.ApplicationJSON)
	if err != nil {
		return nil, err
	}
	var res *SignRes
	err = json.Unmarshal([]byte(result), &res)
	if err != nil {
		return nil, err
	}
	if res.Body.Code != 0 {
		return nil, fmt.Errorf("请求失败，状态码: %d, 响应: %s", res.Body.Code, res.Body.Msg)
	}
	return res.Body, nil
}

// 证书查询请求体
type CertDetailReqBody struct {
	CertSysCode string `json:"certSysCode"`
	CertName    string `json:"certName"`
}

// 证书查询请求
type CertDetailReq struct {
	Header *Header            `json:"header"`
	Body   *CertDetailReqBody `json:"body"`
}

// 证书详情
type CertDetail struct {
	CertSysCode  string       `json:"certSysCode"`
	CertName     string       `json:"certName"`
	IssuerName   string       `json:"issuerName,omitempty"`
	IssueName    string       `json:"issueName,omitempty"`
	KeyAlgo      int          `json:"keyAlgo"`
	CertType     int          `json:"certType"`
	CertUsage    int          `json:"certUsage"`
	User         string       `json:"user"`
	SerialNumber string       `json:"serialNumber"`
	CertPem      string       `json:"certPem"`
	Expiry       string       `json:"expiry"`
	State        int          `json:"state"`
	PubKeyPem    string       `json:"pubKeyPem"`
	Ski          string       `json:"ski"`
	Aki          string       `json:"aki"`
	Pathlen      int          `json:"pathlen"`
	LeafCert     []CertDetail `json:"leafCert"`
	KeyId        string       `json:"keyId,omitempty"`
}

type CertDetailResData struct {
	CertDetail []CertDetail `json:"certDetail"`
}

type CertDetailResBody struct {
	Code int               `json:"code"`
	Data CertDetailResData `json:"data"`
	Msg  string            `json:"msg"`
}

type CertDetailRes struct {
	Header *Header            `json:"header"`
	Body   *CertDetailResBody `json:"body"`
}

// CertDetail 调用证书查询接口 /api/v1/ca/cert/detail
func (c *PKIClient) CertDetail(reqBody *CertDetailReqBody) (*CertDetailResBody, error) {
	req := &CertDetailReq{
		Header: &Header{
			Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		},
		Body: reqBody,
	}
	url := fmt.Sprintf("%s/api/v1/ca/cert/detail", c.ServiceURL)
	result, err := curl.Post(url, req, curl.ApplicationJSON)
	if err != nil {
		return nil, err
	}
	var res *CertDetailRes
	if err := json.Unmarshal([]byte(result), &res); err != nil {
		return nil, err
	}
	if res.Body.Code != 0 {
		return nil, fmt.Errorf("请求失败，状态码: %d, 响应: %s", res.Body.Code, res.Body.Msg)
	}
	return res.Body, nil
}

// 证书查询请求体
type CertSpecificReqBody struct {
	SKI string `json:"ski"`
}

// 证书查询请求
type CertSpecificReq struct {
	Header *Header              `json:"header"`
	Body   *CertSpecificReqBody `json:"body"`
}

// 证书详情
type CertSpecific struct {
	CertSysCode  string `json:"certSysCode"`
	CertName     string `json:"certName"`
	IssuerName   string `json:"issuerName,omitempty"`
	IssueName    string `json:"issueName,omitempty"`
	KeyAlgo      int    `json:"keyAlgo"`
	CertType     int    `json:"certType"`
	CertUsage    int    `json:"certUsage"`
	User         string `json:"user"`
	SerialNumber string `json:"serialNumber"`
	CertPem      string `json:"certPem"`
	Expiry       string `json:"expiry"`
	State        int    `json:"state"`
	PubKeyPem    string `json:"pubKeyPem"`
	Ski          string `json:"ski"`
	Aki          string `json:"aki"`
	Pathlen      int    `json:"pathlen"`
	//LeafCert     []CertDetail `json:"leafCert"`
	KeyId string `json:"keyId,omitempty"`
}

type CertSpecificResBody struct {
	Code int          `json:"code"`
	Data CertSpecific `json:"data"`
	Msg  string       `json:"msg"`
}

type CertSpecificRes struct {
	Header *Header              `json:"header"`
	Body   *CertSpecificResBody `json:"body"`
}

// CertSpecific 调用证书查询接口 /api/v1/ca/cert/specific
func (c *PKIClient) CertSpecific(reqBody *CertSpecificReqBody) (*CertSpecificResBody, error) {
	req := &CertSpecificReq{
		Header: &Header{
			Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		},
		Body: reqBody,
	}
	url := fmt.Sprintf("%s/api/v1/ca/cert/specific", c.ServiceURL)
	result, err := curl.Post(url, req, curl.ApplicationJSON)
	if err != nil {
		return nil, err
	}
	var res *CertSpecificRes
	if err := json.Unmarshal([]byte(result), &res); err != nil {
		return nil, err
	}
	if res.Body.Code != 0 {
		return nil, fmt.Errorf("请求失败，状态码: %d, 响应: %s", res.Body.Code, res.Body.Msg)
	}
	return res.Body, nil
}
