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

func getUserinfo() {
	body := fetch("POST", WoServer+"userInfo", url.Values{
		"date":       {Encrypt(getDate(), getKey())},
		"jsessionid": {Encrypt(getJsessionid(), getKey())},
		"mobile":     {Encrypt(PhoneNumber, getKey())},
	})

	var res struct {
		Userlogo      string
		Username      string
		Grade         int
		Growup        int
		MaxGrowup     int
		Is_distribute string
		Is_share      string
		Status        string
		Message       string
	}

	json.Unmarshal(body, &res)
	if res.Status == "0000" {
		log.Printf("getUserinfo success: username = %s, grade = %d, growup = %d\n",
			res.Username, res.Grade, res.Growup)
	} else {
		log.Println("getUserinfo faild.")
	}
}

func getSigninfo() {
	body := fetch("POST", WoServer+"signInfo", url.Values{
		"jsessionid": {Encrypt(getJsessionid(), getKey())},
		"mobile":     {Encrypt(PhoneNumber, getKey())},
	})

	var res struct {
		Status  string
		Message string
		Data    struct {
			ContinusDay4Week int
			Flowrate         int
			HasSigned        bool
			ContinusDay      int
			SignMonthTotal   int
		}
	}

	json.Unmarshal(body, &res)
	if res.Status == "0" {
		log.Printf("getSigninfo success: Flowrate = %d, HasSigned = %t, ContinusDay = %d\n",
			res.Data.Flowrate, res.Data.HasSigned, res.Data.ContinusDay)
	} else {
		log.Println("getSigninfo failed.")
	}
}

func signAndReceviFlow() {
	body := fetch("POST", WoServer+"signAndReceviFlow", url.Values{
		"dayInt":     {Encrypt("1", getKey())},
		"jsessionid": {Encrypt(getJsessionid(), getKey())},
		"mobile":     {Encrypt(PhoneNumber, getKey())},
	})

	var res struct {
		Status  string
		Message string
		Data    struct {
			LastSignDay      string
			ContinusDay      int
			IsTodayFirstSign bool
			LastSignTime     string
		}
		ReceviFlowData struct {
			ApplyAwardResult struct {
				AwardType  int
				AwardValue int
			}
		}
	}

	json.Unmarshal(body, &res)
	if res.Status == "2" {
		log.Println("signAndReceviFlow success: AwardValue =", res.ReceviFlowData.ApplyAwardResult.AwardValue)
	} else {
		log.Println("signAndReceviFlow failed.")
	}
}

func getUnixMillis() string {
	return strconv.FormatInt(time.Now().UnixNano()/1000000, 10)
}

func initWap() {
	jsessionid, _ := url.QueryUnescape(getJsessionid())
	fetch("GET", "http://wap.17wo.cn/Index.action", url.Values{
		"from":       {"17woclient"},
		"jsessionid": {jsessionid},
	})
}

func luckDraw() {
	body := fetch("GET", "http://wap.17wo.cn/FlowRedPacket!LuckDraw.action", nil)
	log.Println(string(body))

	body = fetch("GET", "http://wap.17wo.cn/FlowRedPacket!share.action", url.Values{
		"sendid":       {""},
		"sharecontent": {"undefined"},
		"subjectId":    {"0"},
		"cpd":          {""},
		"_":            {getUnixMillis()},
	})
	log.Println(string(body))

}

func earnflow() {
	for k := 0; k < 3; k++ {
		body := fetch("GET", "http://wap.17wo.cn/FlowRedPacket!LuckDraw.action", url.Values{
			"pageName": {"earnflow"},
			"_":        {getUnixMillis()},
		})
		log.Println(string(body))
	}
}

func gainTaskAwards() {
	// 任务：登录 ("taskId", "28")
	// 任务：签到 ("taskId", "29")
	// 任务：派红包 ("taskId", "36")
	// 任务：下载一起沃客户端 ("taskId", "38")
	// 任务：订购“365一起沃产品” ("taskId", TODO)
	taskIds := []string{"28", "29"}

	for _, taskId := range taskIds {
		body := fetch("GET", "http://wap.17wo.cn/UserCenterGrowup!gainTaskAwards.action", url.Values{
			"aId":    {"117"},
			"taskId": {taskId},
			"_":      {getUnixMillis()},
		})
		log.Println(string(body))
	}
}

func getStatusOfDiamonds() {
	body := fetch("GET", "http://wap.17wo.cn/DiamondFlow!getStatusOfDiamonds.action", nil)
	log.Println(string(body))
}

func getUserFlowInfo() {
	body := fetch("GET", "http://wap.17wo.cn/DiamondFlow!getUserFlowInfo.action", nil)
	log.Println(string(body))
}

func changeStatusOfDiamonds() {
	diamonds := []string{"green-con", "red-con", "yellow-con"}
	for _, diamond := range diamonds {
		body := fetch("GET", "http://wap.17wo.cn/DiamondFlow!changeStatusOfDiamonds.action", url.Values{
			"diamondButton": {diamond},
		})
		log.Println(string(body))
	}
}

func getTurnAwardLuckDraw() {
	body := fetch("GET", "http://wap.17wo.cn/PlayTurntable!getTurnAwardLuckDraw.action", url.Values{
		"_": {getUnixMillis()},
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

	// app
	getUserinfo()
	getSigninfo()
	signAndReceviFlow()

	// wap
	initWap()
	luckDraw()
	earnflow()
	gainTaskAwards()
	getStatusOfDiamonds()
	getUserFlowInfo()
	changeStatusOfDiamonds()
	getTurnAwardLuckDraw()

	log.Println("===== wo.go end =====\n")
}
