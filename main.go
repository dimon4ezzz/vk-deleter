package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const clientId = ""
const clientSecret = ""
const apiVersion = "5.131"

var client http.Client
var token string

type OauthResponse struct {
	URI   string `json:"redirect_uri,omitempty"`
	Token string `json:"access_token,omitempty"`
}

type ApiResponse struct {
	Response string        `json:"response,omitempty"`
	Error    ErrorResponse `json:"error,omitempty"`
}

type ErrorResponse struct {
	ErrorCode    int    `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

func main() {
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal("не удалось создать CookieJar", err)
	}
	client = http.Client{
		Jar: cookieJar,
	}

	oauthQuery := url.Values{}
	oauthQuery.Set("client_id", clientId)
	oauthQuery.Add("client_secret", clientSecret)
	oauthQuery.Add("grant_type", "password")
	oauthQuery.Add("version", apiVersion)
	oauthQuery.Add("2fa_supported", "1")

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter VK login: ")
	login, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal("не удалось прочесть логин\n", err)
	}
	oauthQuery.Add("username", strings.TrimSpace(login))

	fmt.Print("Enter VK password: ")
	password, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal("не удалось прочесть пароль\n", err)
	}
	oauthQuery.Add("password", strings.TrimSpace(password))

	oauthUrl := &url.URL{
		Scheme:   "https",
		Host:     "oauth.vk.com",
		Path:     "token",
		RawQuery: oauthQuery.Encode(),
	}
	oauthResponse := &OauthResponse{}
	fillStructFromResponse(oauthUrl.String(), oauthResponse)
	if oauthResponse.Token != "" {
		token = oauthResponse.Token
	} else { // 2fa required
		authHtml := getBytesFromResponse(oauthResponse.URI)
		authHashReg := regexp.MustCompile("authcheck_code&hash=([^\"]+)")
		hash := string((authHashReg.FindSubmatch(authHtml))[1])
		fmt.Print("Enter 2fa code: ")
		code, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal("не удалось прочесть пароль\n", err)
		}
		loginQuery := url.Values{}
		loginQuery.Set("act", "authcheck_code")
		loginQuery.Add("hash", hash)
		loginQuery.Add("code", strings.TrimSpace(code))
		loginUrl := &url.URL{
			Scheme:   "https",
			Host:     "m.vk.com",
			Path:     "login",
			RawQuery: loginQuery.Encode(),
		}
		loginResp, err := client.Get(loginUrl.String())
		if err != nil {
			log.Fatal("не удалось сделать логин", err)
		}
		defer loginResp.Body.Close()
		if loginResp.StatusCode != 200 {
			log.Fatal("код не 200"+strconv.Itoa(loginResp.StatusCode)+"\n", err)
		}
		fragment := loginResp.Request.URL.Fragment
		loginResp.Body.Close()
		tokenReg := regexp.MustCompile("access_token=([^&]+)")
		token = (tokenReg.FindStringSubmatch(fragment))[1]
	}

	_, err = os.Stat("./comments")
	if os.IsNotExist(err) {
		log.Println("Папка `comments` не найдена\n" +
			"скачайте архив с установленной галочкой «Комментарии»\n" +
			"https://vk.com/data_protection?section=rules&scroll_to_archive=1\n" +
			"и положите экзешник в распакованную папку архива")
		return
	}

	files, err := os.ReadDir("./comments")
	if err != nil {
		log.Fatal("Папку `comments` не удалось прочесть\n", err)
	}

	commentDescriptionReg := regexp.MustCompile("<div class='item__main'><a href=\"https://vk.com/wall(-?\\d+)_\\d+\\?reply=(\\d+)\">")
	for _, f := range files {
		content, err := os.ReadFile("./comments/" + f.Name())
		if err != nil {
			log.Fatal("Файл "+f.Name()+" нельзя прочитать\n", err)
		}
		fmt.Println("Я смотрю файл " + f.Name())
		groups := commentDescriptionReg.FindAllSubmatch(content, -1)
		for _, gr := range groups {
			query := url.Values{}
			query.Set("owner_id", string(gr[1]))
			query.Add("comment_id", string(gr[2]))
			query.Add("access_token", token)
			query.Add("v", apiVersion)
			ok := doApiCall("wall.deleteComment", query)
			if ok {
				log.Println("ok")
			} else {
				log.Println("не удалось удалить: ", string((gr[0])[33:]))
			}
		}
	}
}

func getBytesFromResponse(url string) []byte {
	resp, err := client.Get(url)
	if err != nil {
		log.Fatal("ошибка сети при вызове "+url+"\n", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		log.Fatal("ошибка авторизации")
	}
	if resp.StatusCode != 200 {
		log.Fatal("ошибка вызова "+url+"\n", strconv.Itoa(resp.StatusCode))
	}
	text, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("не удалось прочитать респонс из "+url+"\n", err)
	}
	return text
}

func fillStructFromResponse(url string, obj interface{}) {
	resp, err := client.Get(url)
	if err != nil {
		log.Fatal("ошибка сети при вызове "+url+"\n", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		log.Fatal("ошибка авторизации")
	}
	if resp.StatusCode != 200 {
		log.Fatal("ошибка вызова "+url+"\n", strconv.Itoa(resp.StatusCode))
	}
	err = json.NewDecoder(resp.Body).Decode(obj)
	if err != nil {
		log.Fatal("не удалось распарсить ответ "+url+"\n", err)
	}
}

func doApiCall(method string, query url.Values) bool {
	uri := &url.URL{
		Scheme:   "https",
		Host:     "api.vk.com",
		Path:     "method/" + method,
		RawQuery: query.Encode(),
	}
	apiResponse := &ApiResponse{}
	fillStructFromResponse(uri.String(), apiResponse)
	if apiResponse.Response != "" {
		return true
	}
	switch apiResponse.Error.ErrorCode {
	case 211:
		log.Println("уже удалено или недоступно (211)")
		return false
	case 15:
		log.Println("⛔ стена недоступна! (15) ⛔ контент может быть использован против вас ⛔ проверьте контент по ссылке ⛔")
		return false
	case 30:
		log.Println("⛔ контент на приватной стене, добавьтесь в друзья (30) ⛔ контент может быть использован против вас ⛔ проверьте контент по ссылке ⛔")
		return false
	case 9:
		log.Fatal("API больше недоступно из-за большого количества запросов, попробуйте завтра")
	case 6:
		time.Sleep(1 * time.Second)
		return doApiCall(method, query)
	}
	log.Println("ошибка " + strconv.Itoa(apiResponse.Error.ErrorCode) + ": " + apiResponse.Error.ErrorMessage)
	return false
}
