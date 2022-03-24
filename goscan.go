package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type result struct {
	ip    string
	ports []int
}

type results struct {
	ipPorts map[string][]int
	mutex   sync.Mutex
}

func NewResults() results {
	ipPorts := make(map[string][]int)
	return results{
		ipPorts: ipPorts,
		mutex:   sync.Mutex{},
	}
}

func (r *results) Add(ip string, port int) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.ipPorts[ip] = append(r.ipPorts[ip], port)
}

func (r *results) Print() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	for ip, ports := range r.ipPorts {
		sort.Ints(ports)
		fmt.Printf("Results for %v\n--------------\n", ip)
		for _, p := range ports {
			fmt.Printf("%d - open\n", p)
		}
		fmt.Print("--------------\n")
	}
}

func (r *results) PrintOnlyPorts() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	var allPorts []int

	for _, ports := range r.ipPorts {
		allPorts = append(allPorts, ports...)
	}

	allPorts = removeDuplicatesInts(allPorts)

	sort.Ints(allPorts)

	for i, port := range allPorts {
		fmt.Printf("%v", port)
		if i+1 != len(allPorts) {
			fmt.Print(",")
		}
	}
}

const numberOfPorts int = 65535

var ip string
var pathToList string
var threads int
var timeoutMs int
var retries int
var onlyPorts bool

func init() {
	flag.StringVar(&ip, "ip", "", "ip address to scan")
	flag.IntVar(&threads, "threads", runtime.NumCPU(), "threads (Defaults to system's number of CPUs)")
	flag.IntVar(&timeoutMs, "timeout", 100, "timeout (ms)")
	flag.IntVar(&retries, "retries", 3, "retries to one port")
	flag.StringVar(&pathToList, "list", "", "path to list of IPs")
	flag.BoolVar(&onlyPorts, "only-ports", false, "output only ports to use in future nmap scan (eg. 22,23,25)")

}

func main() {

	flag.Parse()

	ips := targets()

	results := NewResults()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		if onlyPorts {
			results.PrintOnlyPorts()
		} else {
			results.Print()
		}
		os.Exit(0)
	}()

	for _, ip := range ips {

		portsChan := make(chan int, threads)
		openPortsChan := make(chan int, threads)

		for w := 1; w <= threads; w++ {
			go worker(portsChan, openPortsChan, ip, time.Millisecond*time.Duration(timeoutMs))
		}

		go func() {
			for j := 1; j <= numberOfPorts; j++ {
				portsChan <- j
			}
			close(portsChan)
			close(openPortsChan)
		}()

		for openPort := range openPortsChan {
			results.Add(ip, openPort)
		}

	}

	if onlyPorts {
		results.PrintOnlyPorts()
	} else {
		results.Print()
	}

}

func targets() []string {
	var ips []string

	if pathToList != "" {
		listIps, err := readListIPs(pathToList)
		if err != nil {
			log.Fatalln(err)
		}
		ips = listIps
	}

	if ip != "" {
		ips = []string{ip}
	}

	return ips
}

func printPorts(ports []int) string {
	if len(ports) > 1 {
		return ""
	}
	var str string
	for _, port := range ports {
		str = str + strconv.Itoa(port)
	}
	return str
}

func scanport(ip string, port int, timeout time.Duration) bool {
	target := fmt.Sprintf("%s:%s", ip, strconv.Itoa(port))

	for i := 0; i < retries; i++ {
		conn, err := net.DialTimeout("tcp", target, timeout)
		if err == nil {
			conn.Close()
			return true
		}
		if strings.Contains(err.Error(), "too many open files") {
			log.Fatalf("error: %v, decrease number of threads", err)
		}

		if !strings.Contains(err.Error(), "connection refused") &&
			!strings.Contains(err.Error(), "i/o timeout") {
			fmt.Println(err)
		}

	}
	return false
}

func worker(jobs <-chan int, openPortsChan chan<- int, ip string, timeout time.Duration) {
	for port := range jobs {
		open := scanport(ip, port, timeout)
		if open {
			openPortsChan <- port
		}
	}
}

func printResults(results []result) {
	for _, result := range results {
		ports := result.ports
		sort.Ints(ports)
		fmt.Printf("Results for %v\n--------------\n", result.ip)
		for _, p := range ports {
			fmt.Printf("%d - open\n", p)
		}
	}
}

func readListIPs(path string) ([]string, error) {
	var validIps []string

	lines, err := readLines(path)
	if err != nil {
		return nil, fmt.Errorf("cant read the file: %w", err)
	}

	for _, line := range lines {
		ip := net.ParseIP(line)
		if ip.To4() != nil {
			validIps = append(validIps, line)
		}
	}

	if len(validIps) < 1 {
		return nil, errors.New("no valid ips in the list")
	}

	return validIps, nil
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	lines = removeDuplicatesStr(lines)

	return lines, nil
}

func removeDuplicatesStr(strs []string) []string {
	var returnSlice []string

	m := make(map[string]struct{})
	for i := range strs {
		m[strs[i]] = struct{}{}
	}

	for k := range m {
		returnSlice = append(returnSlice, k)
	}

	return returnSlice
}

func removeDuplicatesInts(ints []int) []int {
	var returnSlice []int

	m := make(map[int]struct{})
	for i := range ints {
		m[ints[i]] = struct{}{}
	}

	for k := range m {
		returnSlice = append(returnSlice, k)
	}

	return returnSlice

}
