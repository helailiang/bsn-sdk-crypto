package key

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"

	ec "github.com/BSNDA/bsn-sdk-crypto/crypto/ecdsa"
	"github.com/BSNDA/bsn-sdk-crypto/pkg/pki"
	"github.com/BSNDA/bsn-sdk-crypto/types"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"
)

// HuaweiCloudKMSPrivateKeyProvider 实现 PrivateKeyProvider 接口
type PKIPrivateKeyProvider struct {
	keyId     string            // KMS 中密钥的 ID
	publicKey PublicKeyProvider // 缓存公钥（KMS 通常不返回私钥）
	algo      types.KeyType     // 算法类型（ECDSA, SM等）
	PKIClient *pki.PKIClient
	pubKeyPem []byte
}

func formatBytesAsHexString(bytes []byte) string {
	hexString := ""
	for _, b := range bytes {
		hexString += strings.ToUpper(fmt.Sprintf("%02x:", b))
	}
	// 去掉最后一个冒号
	return hexString[:len(hexString)-1]
}

func NewPKIPrivateKeyProvider(serviceURL string, certPEM string) (*PKIPrivateKeyProvider, error) {
	parsedCa, err := helpers.ParseCertificatePEM([]byte(certPEM))
	if err != nil {
		log.Errorf("Parse Cert error:%s", err)
		return nil, err
	}
	certSki := formatBytesAsHexString(parsedCa.SubjectKeyId)
	PKIClient := pki.NewPKIClient(serviceURL)
	certSpecificResBody, err := PKIClient.CertSpecific(&pki.CertSpecificReqBody{SKI: certSki})
	if err != nil {
		log.Errorf("call pki sever get cert specific by ski:%s error:%s", certSki, err)
		return nil, err
	}
	if len(certSpecificResBody.Data.KeyId) < 1 {
		err = errors.Errorf("call pki sever get cert specific KeyId is null by ski:%s ", certSki)
		return nil, err
	}
	return &PKIPrivateKeyProvider{
		PKIClient: pki.NewPKIClient(serviceURL),
		keyId:     certSpecificResBody.Data.KeyId,
		pubKeyPem: []byte(certSpecificResBody.Data.PubKeyPem),
	}, nil
}

func (e *PKIPrivateKeyProvider) Key() interface{} {

	panic("pki服务不可获取密钥 Key()")
}

func (e *PKIPrivateKeyProvider) Bytes() []byte {
	panic("pki服务不可获取密钥 Bytes()")
}

func (e *PKIPrivateKeyProvider) KeyPEM() ([]byte, error) {
	panic("pki服务不可 KeyPEM()")
}

func (e *PKIPrivateKeyProvider) SKI() []byte {
	panic("pki服务不可 SKI()")
}

func (e *PKIPrivateKeyProvider) PublicKey() PublicKeyProvider {
	log.Info("pki 获取 PublicKey()")

	pemBytes := e.pubKeyPem // SubjectPublicKeyInfo DER
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		panic("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(fmt.Errorf("failed to parse DER public key: %v", err))
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		panic("not ECDSA public key")
	}
	return &ecdsaPublicKey{
		key: ecPub,
	}
}

func (e *PKIPrivateKeyProvider) Algorithm() types.KeyType {
	return types.ECDSA_R1
	//if reflect.TypeOf(e.key.Curve) == reflect.TypeOf(elliptic.P256()) {
	//	return types.ECDSA_R1
	//} else {
	//	return types.ECDSA_K1
	//}

}

func (e *PKIPrivateKeyProvider) Hash(msg []byte) []byte {
	log.Info("调用pki进行Hash()")

	h := sha256.New()

	h.Write(msg)
	hash := h.Sum(nil)

	return hash
}

func (e *PKIPrivateKeyProvider) Sign(digest []byte) ([]byte, error) {
	log.Info("调用pki进行签名")
	return e.SignWithKMS(digest)
	//return ec.SignECDSA(e.key, digest)

}

// asn1ECDSASig is for parsing DER signature from KMS

type ECDSASignature struct {
	R, S *big.Int
}

func marshalECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ECDSASignature{r, s})
}

// SignWithKMS: 使用 KMS 对传入的 digest (已是 hash) 进行签名，并返回 Fabric 期望的 ASN.1(r,s) bytes（且已 low-S）
func (e *PKIPrivateKeyProvider) SignWithKMS(digest []byte) ([]byte, error) {

	// 1) 调用 KMS Sign API，注意 MessageType = DIGEST
	signOut, err := e.PKIClient.Sign(&pki.SignReqBody{
		KeyId:       e.keyId,
		SignAlgo:    "ECDSA_SHA_256", // HUAWEI
		Input:       base64.StdEncoding.EncodeToString(digest),
		Provider:    "",
		MessageType: "DIGEST",
	})
	if err != nil {
		return nil, err
	}
	//sigDER := signOut.Data.Signature // []byte
	//
	sigDER, err := base64.StdEncoding.DecodeString(signOut.Data.Signature)
	if err != nil {
		return nil, err
	}
	// 2) 从 KMS 获取公钥，以便做 ToLowS（需要 ecdsa.PublicKey）

	pemBytes := e.pubKeyPem // SubjectPublicKeyInfo DER
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pubIfc, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pubKey, ok := pubIfc.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ECDSA")
	}

	// 3) 解析 KMS 返回的 ASN.1 DER -> r,s
	var asn1Sig ECDSASignature
	if _, err := asn1.Unmarshal([]byte(sigDER), &asn1Sig); err != nil {
		return nil, err
	}
	if asn1Sig.R == nil || asn1Sig.S == nil {
		return nil, errors.New("invalid signature from KMS")
	}

	// 4) 做 ToLowS（使用 Fabric 的 utils）
	lowS, _, err := ec.ToLowS(pubKey, asn1Sig.S)
	if err != nil {
		return nil, err
	}

	// 5) Marshal 回 ASN.1 格式（Fabric 原先的 return）
	out, err := marshalECDSASignature(asn1Sig.R, lowS)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (e *PKIPrivateKeyProvider) SignTx(digest []byte) (r, s, v *big.Int, err error) {

	panic("pki服务不可 SignTx()")
	//if e.Algorithm() == types.ECDSA_K1 {
	//	return eth.SignData(e.key, digest)
	//} else {
	//	sig, err := crypto.Sign(digest, e.key)
	//	if err != nil {
	//		return nil, nil, nil, err
	//	}
	//
	//	r = new(big.Int).SetBytes(sig[:32])
	//	s = new(big.Int).SetBytes(sig[32:64])
	//	v = new(big.Int).SetBytes([]byte{sig[64] + 27})
	//	return r, s, v, nil
	//}
}

func (e *PKIPrivateKeyProvider) GenCSR(req *csr.CertificateRequest) ([]byte, error) {
	panic("pki服务不可 GenCSR()")
	//if req.KeyRequest == nil {
	//	req.KeyRequest = newCfsslBasicKeyRequest()
	//}
	//
	//if e.Algorithm() == types.ECDSA_R1 {
	//	return csr.Generate(e.key, req)
	//} else {
	//	return nil, errors.New("not supported")
	//}
}

// 新增一个配置类型，用于区分本地密钥和云 KMS 密钥
type KeyConfig struct {
	Type       string // "local" 或 "huaweicloud-kms"
	Algo       types.KeyType
	PrivatePEM string // 本地 私钥PEM
	KeyID      string // KMS Key ID
	ServiceURL string // PKI 服务地址
	CertPEM    string // 证书
}

func NewPrivateKeyProviderByType(config KeyConfig) (PrivateKeyProvider, error) {
	switch config.Type {
	case "local":
		// 复用原有逻辑
		switch config.Algo {
		case types.ECDSA_R1, types.ECDSA_K1:
			return NewECDSDAPrivateKey(config.PrivatePEM)
		case types.SM:
			return NewSMPrivateKey(config.PrivatePEM)
		}
	case "PKI":
		return NewPKIPrivateKeyProvider(config.ServiceURL, config.CertPEM)
	}

	return nil, errors.Errorf("Unsupported key type: %s", config.Type)
}
