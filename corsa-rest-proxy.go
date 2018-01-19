package main

import (
	"crypto/tls"
	"fmt"
	"github.com/gorilla/mux"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/resty.v1"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var HEADER_CONTENT_TYPE string = "application/json"
var HEADER_ACCEPT string = "text/plain"
var HEADER_AUTHORIZATION string = "5bc3ffef46292d001514ed331201dc4dd844499e147c6432105501f300fe34916703bfe3ca45001f85d2860866d1d8ded78ad39fd8538dd79e3b6e879860b6a7"
var NSE string = "eval01nse01.corp"
var SECURITY_API_PATH = "/app/rules/vsc1/v1/sources/rest/rules"
var GIGAFILTER_API_PATH = "/api/v1/gigafilter"

func rest_get(nse, auth_code string) string {
	resty.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	resp, err := resty.R().
		SetHeader("Content-Type", HEADER_CONTENT_TYPE).
		SetHeader("Accept", HEADER_ACCEPT).
		SetHeader("Authorization", auth_code).
		Get("https://" + nse + SECURITY_API_PATH)
	if err != nil {
		fmt.Printf("\nError: %v", err)
	}
	//fmt.Printf("\nResponse Status Code: %v", resp.StatusCode())
	//fmt.Printf("\nResponse Status: %v", resp.Status())
	fmt.Printf("\nResponse Body: %v", resp)
	//fmt.Printf("\nResponse Time: %v", resp.Time())
	//fmt.Printf("\nResponse Recevied At: %v", resp.ReceivedAt())
	return resp.String()
}

func rest_post(nse, auth_code, ipv4_addr string) string {
	resty.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	var rule_int int = rand.Intn(999999) + 1000000
	var rule_id string = strconv.Itoa(rule_int)
	var body string = `{"rule":` + rule_id + `,"afi":"ipv4","filters":{"src-ip":"` + ipv4_addr + `"},"actions":[{"action-type":"discard"}]}`
	resp, err := resty.R().
		SetHeader("Content-Type", HEADER_CONTENT_TYPE).
		SetHeader("Accept", HEADER_ACCEPT).
		SetHeader("Authorization", auth_code).
		SetBody([]byte(body)).
		//SetBody([]byte(`{"rule":1, "afi":"ipv4","filters":{"src-ip":"1.1.1.2"}}`)).
		//SetBody(byte[]('{"rule":"1","afi":"ipv4","filters":{"src-ip":"[1.1.1.2]"},"actions":[{"action-type":"discard"}]}')).
		Post("https://" + nse + SECURITY_API_PATH)
	if err != nil {
		fmt.Printf("\nError: %v", err)
	}
	//fmt.Printf("\nResponse Status Code: %v", resp.StatusCode())
	//fmt.Printf("\nResponse Status: %v", resp.Status())
	fmt.Printf("\nResponse Body: %v", resp)
	//fmt.Printf("\nResponse Time: %v", resp.Time())
	//fmt.Printf("\nResponse Recevied At: %v", resp.ReceivedAt())
	return resp.String()
}

func rest_delete(nse, auth_code, rule_id string) string {
	resty.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	resp, err := resty.R().
		SetHeader("Content-Type", HEADER_CONTENT_TYPE).
		SetHeader("Accept", HEADER_ACCEPT).
		SetHeader("Authorization", auth_code).
		Delete("https://" + nse + SECURITY_API_PATH + "/" + rule_id)
	if err != nil {
		fmt.Printf("\nError: %v", err)
	}
	//fmt.Printf("\nResponse Status Code: %v", resp.StatusCode())
	//fmt.Printf("\nResponse Status: %v", resp.Status())
	fmt.Printf("\nResponse Body: %v", resp)
	//fmt.Printf("\nResponse Time: %v", resp.Time())
	//fmt.Printf("\nResponse Recevied At: %v", resp.ReceivedAt())
	return resp.String()
}

func rest_gigafilter_patch(nse, auth_code, action, ipv4_addr string) string {
	resty.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	var ifaction string = action
	var body string
	if strings.EqualFold(ifaction, "add") {
		body = `[{"op":"` + action + `","path":"/ipv4","value":"` + ipv4_addr + `"}]`
	}
	if strings.EqualFold(ifaction, "remove") {
		body = `[{"op":"` + action + `","path":"/ipv4/` + ipv4_addr + `"}]`
	}
	resp, err := resty.R().
		SetHeader("Content-Type", HEADER_CONTENT_TYPE).
		SetHeader("Accept", HEADER_ACCEPT).
		SetHeader("Authorization", auth_code).
		SetBody([]byte(body)).
		Patch("https://" + nse + GIGAFILTER_API_PATH)
	if err != nil {
		fmt.Printf("\nError: %v", err)
	}
	//fmt.Printf("\nResponse Status Code: %v", resp.StatusCode())
	//fmt.Printf("\nResponse Status: %v", resp.Status())
	fmt.Printf("\nResponse Body: %v", resp)
	//fmt.Printf("\nResponse Time: %v", resp.Time())
	//fmt.Printf("\nResponse Recevied At: %v", resp.ReceivedAt())
	return resp.String()
}

var (
	addr_port = kingpin.Arg("addr_port", "Addr:Port to run rest proxy on.").Required().String()
	nse       = kingpin.Arg("nse", "FQDN or IP Address of NSE.").Required().String()
	auth_code = kingpin.Arg("auth_code", "NSE Authorization Code.").Required().String()
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())
	kingpin.Parse()
	fmt.Printf("%v, %s\n", *nse, *auth_code)
	// Built-in Tests
	//rest_get(*nse, *auth_code)
	//rest_post(*nse, *auth_code, "1.1.1.1")
	//rest_gigafilter_patch(*nse, *auth_code, "add", "2.2.2.2")
	//rest_gigafilter_patch(*nse, *auth_code, "remove", "2.2.2.2")
	//rest_delete(*nse, *auth_code, "1")

	handle_rest_get := func(w http.ResponseWriter, r *http.Request) {
		rest_get(*nse, *auth_code)
	}
	handle_rest_post := func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		//fmt.Fprintf(w, "IPv4 Address Blocked: %v\n", vars["ipv4_addr"])
		var ipv4_addr string = vars["ipv4_addr"]
		rest_post(*nse, *auth_code, ipv4_addr)
	}
	handle_rest_delete := func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		//fmt.Fprintf(w, "IPv4 Address Blocked: %v\n", vars["ipv4_addr"])
		var rule_id string = vars["rule_id"]
		rest_delete(*nse, *auth_code, rule_id)
	}
	handle_gigafilter_post := func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		//fmt.Fprintf(w, "IPv4 Address Blocked: %v\n", vars["ipv4_addr"])
		var ipv4_addr string = vars["ipv4_addr"]
		rest_gigafilter_patch(*nse, *auth_code, "add", ipv4_addr)
	}
	handle_gigafilter_delete := func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		//fmt.Fprintf(w, "IPv4 Address Blocked: %v\n", vars["ipv4_addr"])
		var ipv4_addr string = vars["ipv4_addr"]
		rest_gigafilter_patch(*nse, *auth_code, "remove", ipv4_addr)
	}

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/block/get", handle_rest_get).Methods("GET")
	router.HandleFunc("/block/add/{ipv4_addr}", handle_rest_post).Methods("GET")
	router.HandleFunc("/block/delete/{rule_id}", handle_rest_delete).Methods("GET")
	router.HandleFunc("/gigafilter/add/{ipv4_addr}", handle_gigafilter_post).Methods("GET")
	router.HandleFunc("/gigafilter/remove/{ipv4_addr}", handle_gigafilter_delete).Methods("GET")

	srv := &http.Server{
		Handler: router,
		Addr:    *addr_port,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
