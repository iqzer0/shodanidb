package main

import (
	"bufio"
	"encoding/json"
	"github.com/apoorvam/goterminal"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
	"os"
	"strings"
	"sync"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/mapcidr"
)

type Response struct {
	CPES	[]string
	Hostnames	[]string
	IP	string
	Ports	[]int32
	Tags	[]string
	Vulns	[]string
}

func main() {
	var noCPEs bool
	flag.BoolVar(&noCPEs, "nc", false, "Hide CPEs")

	var noHostnames bool
	flag.BoolVar(&noHostnames, "nh", false, "Hide hostnames")

	var noTags bool
	flag.BoolVar(&noTags, "nt", false, "Hide tags")

	var noVulns bool
	flag.BoolVar(&noVulns, "nv", false, "Hide vulnerabilities")

	var noColor bool
	flag.BoolVar(&noColor, "nocolor", false, "Disable color in output")

	var jsonFile string
	flag.StringVar(&jsonFile, "json", "", "Save output to JSON format")

	var verbose bool
	flag.BoolVar(&verbose, "v", false, "Verbose")

	flag.Parse()


	var inputs, targets []string

	if flag.NArg() > 0 {
		inputs = []string{flag.Arg(0)}
	} else {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			inputs = append(inputs, sc.Text())
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
		}
	}

	targets = loadTargets(inputs, verbose)
	channel := make(chan Response)
	var wg sync.WaitGroup
	total := len(targets)
	writer := goterminal.New(os.Stdout)
	for i := 0; i < len(targets); i++ {

		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			jsonData := getData(targets[i], verbose)
			channel <- jsonData
		}()
	}
	
	go func() {
		wg.Wait()
		close(channel)
	}()

	if jsonFile != "" {
		saveJson(channel, jsonFile)
		return
	}
	
	for i := 0; i < len(targets); i++ {
		printResult(<-channel, noCPEs, noHostnames, noTags, noVulns, noColor)
		fmt.Fprintf(writer, "Scanning (%d/%d) hosts...\n", i,total)
		writer.Print()
		time.Sleep(time.Millisecond * 5)
		writer.Clear()
	}
	writer.Reset()
}


func loadTargets(inputs []string, verbose bool) []string {

	var targets []string

	for _, target := range inputs {
		if iputil.IsCIDR(target) {
			cidrIps, err := mapcidr.IPAddresses(target)
			if err != nil {
				if verbose {
					log.Printf("Couldn't parse CIDR!\n")
				}
				return []string{}
			}
			for _, ip := range cidrIps {
				targets = append(targets, ip)
			}
		} else {
			targets = append(targets, target)
		}
	}
	return targets
}


func getData(ip string, verbose bool) Response {
	url := fmt.Sprintf("https://internetdb.shodan.io/%s", ip)
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("User-Agent", `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.27 Safari/537.36`)
	req.Header.Add("Connection", "close")
	req.Close = true
	res, err := client.Do(req)
	if err != nil {
		if verbose {
			log.Printf("Couldn't connect to the server! (%s)", ip)
			log.Printf("%s\n", err)
		}		
		return Response{}
	}
	raw, err := ioutil.ReadAll(res.Body)
	if err != nil {
		if verbose {
			log.Printf("Couldn't read the data from %s", ip)
			log.Printf("%s\n", raw)
		}
		return Response{}
	}
	res.Body.Close()
	var jsonData Response
	err = json.Unmarshal(raw, &jsonData)
	if err != nil {
		if verbose {
			log.Printf("The data from %s is incorrect!", ip)
			log.Printf("%s\n", raw)
		}
		return Response{}
	}
	return jsonData
}


func saveJson(chData chan Response, jsonFile string) {
	var jsonDatas []Response
	for jsonData := range chData {
		if jsonData.IP != "" {
			jsonDatas = append(jsonDatas, jsonData)
		}
	}
	if len(jsonDatas) != 0 {
		stringData, _ := json.Marshal(jsonDatas)
		_ = ioutil.WriteFile(jsonFile, stringData, 0644)
	}
}


func printResult(jsonData Response, noCPEs bool, noHostnames bool, noTags bool, noVulns bool, noColor bool) {
	builder := &strings.Builder{}
	if jsonData.IP == "" {
		return
	}

	builder.WriteString(jsonData.IP + "\t")

	ports := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(jsonData.Ports)), ", "), "[]")

	if !noColor {
		builder.WriteString(aurora.Green(ports).String())
	} else {
		builder.WriteString(ports)
	}

	if (!noCPEs && len(jsonData.CPES) > 0) {
		cpes := strings.Join(jsonData.CPES, ", ")
		if !noColor {
			builder.WriteString("\tCPEs: " + aurora.Yellow(cpes).String())
		} else {
			builder.WriteString("\tCPEs: " + cpes)
		}
	}

	if (!noVulns && len(jsonData.Vulns) > 0) {
		vulns := strings.Join(jsonData.Vulns, ", ")
		if !noColor {
			builder.WriteString("\tVulnerabilities: " + aurora.Red(vulns).String())
		} else {
			builder.WriteString("\tVulnerabilities: " + vulns)
		}
	}

	if (!noHostnames && len(jsonData.Hostnames) > 0) {
		hostnames := strings.Join(jsonData.Hostnames, ", ")
		if !noColor {
			builder.WriteString("\t Hostnames: " + aurora.Blue(hostnames).String())
		} else {
			builder.WriteString("\tHostnames: " + hostnames)
		}
	}

	if (!noTags && len(jsonData.Tags) > 0) {
		tags := strings.Join(jsonData.Tags, ", ")
		if !noColor {
			builder.WriteString("\tTags: " + aurora.Magenta(tags).String())
		} else {
			builder.WriteString("\tTags: " + tags)
		}
	}

	fmt.Println(builder.String())
}
