package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"time"
)

var (
	IV          []byte = []byte{1, 2, 3, 4, 5, 6, 7, 8}
	WoServer    string = "http://112.96.28.144:8080/woserver/"
	PhoneNumber string = os.Getenv("WO_PHONENUMBER")
	Password    string = os.Getenv("WO_PASSWORD")
	Key         string
	Jsessionid  string
	Client      *http.Client
)

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func DesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	origData = PKCS5Padding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, IV)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func Encrypt(origData, key string) string {
	crypted, err := DesEncrypt([]byte(origData), []byte(key))
	if err != nil {
		log.Panicln(err)
	}
	return base64.StdEncoding.EncodeToString(crypted)
}

func getDate() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func fetch(method, urlStr string, values url.Values) []byte {
	var req *http.Request
	var err error

	if method == "POST" {
		req, err = http.NewRequest(method, urlStr, bytes.NewBufferString(values.Encode()))
		if err != nil {
			log.Panicln(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "")
	} else if method == "GET" {
		req, err = http.NewRequest(method, urlStr, nil)
		if err != nil {
			log.Panicln(err)
		}
		req.URL.RawQuery = values.Encode()
		req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 5.1.1; Nexus 5 Build/LMY48B; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/43.0.2357.65 Mobile Safari/537.36")
	} else {
		log.Fatalln("fetch failed: unknow method", method)
	}

	resp, err := Client.Do(req)
	if err != nil {
		log.Panicln(err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Panicln(err)
	}
	return body
}

func getKey() string {
	if Key != "" {
		return Key
	}

	body := fetch("POST", WoServer+"woclient", url.Values{
		"u": {Encrypt("17woclient"+getDate(), "17woclient"[0:8])},
	})

	var res struct {
		Status string
		U      string
	}

	json.Unmarshal(body, &res)
	if res.Status == "0" && len(res.U) == 8 {
		Key = res.U
		log.Println("getKeyFromRemote:", Key)
	} else {
		log.Fatalln("getKeyFromRemote failed.")
	}

	return Key
}

func getJsessionid() string {
	if Jsessionid != "" {
		return Jsessionid
	}

	// login phase 1 / 2
	body := fetch("POST", WoServer+"login", url.Values{
		"loginType": {Encrypt("1", getKey())},
		"mobile":    {Encrypt(PhoneNumber, getKey())},
		"password":  {Encrypt(Password, getKey())},
		"username":  {""},
	})

	var res struct {
		Code   string
		Result struct {
			ResultCode    int
			ResultMessage string
			Properties    struct {
				Jsessionid string
			}
		}
	}

	json.Unmarshal(body, &res)
	if res.Code == "00000000" && res.Result.ResultCode == 0 {
		log.Println("login phase 1 / 2 success.")
	} else {
		log.Fatalln("login phase 1 / 2 failed.")
	}

	// login phase 2 / 2
	body = fetch("POST", WoServer+"woClientLoginServlet", url.Values{
		"phone_number": {Encrypt(PhoneNumber, getKey())},
	})

	json.Unmarshal(body, &res)
	if res.Code == "00000000" && res.Result.ResultCode == 0 {
		Jsessionid = res.Result.Properties.Jsessionid
		log.Println("login phase 2 / 2 success:", "Jsessionid =", Jsessionid)
	} else {
		log.Fatalln("login phase 2 / 2 failed.")
	}

	return Jsessionid
}

func getUnixMillis() string {
	return strconv.FormatInt(time.Now().UnixNano()/1000000, 10)
}

func loginWeb() {
	jsessionid, _ := url.QueryUnescape(getJsessionid())
	fetch("GET", "http://17wo.cn/Index.action", url.Values{
		"from":       {"17woclient"},
		"jsessionid": {jsessionid},
	})
}

func get300MB() {
	body := fetch("GET", "http://17wo.cn/FlowRateAccount!receiveFlowPacket.action", url.Values{
		"packageid": {"3"},
		"_":         {getUnixMillis()},
	})
	log.Println(string(body))
}
func get200MB() {
	body := fetch("GET", "http://17wo.cn/FlowRateAccount!receiveFlowPacket.action", url.Values{
		"packageid": {"5"},
		"_":         {getUnixMillis()},
	})
	log.Println(string(body))
}

func main() {
	log.Println("===== wo.go start =====")

	// init
	cj, _ := cookiejar.New(nil)
	Client = &http.Client{
		Jar: cj,
	}

	// web
	loginWeb()
	get300MB()
	get200MB()

	log.Println("===== wo.go end =====\n")
}

