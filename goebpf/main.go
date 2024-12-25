package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/dropbox/goebpf"
)

type ipAddressList []string

type Config struct {
	InterfaceName     string
	PPS               uint64
	BPS               uint64
	Ipv4BlacklistTemp []string //用户初始自定义的可动态封锁的黑名单列表
	Ipv4BlacklistPerm []string //永久封锁的黑名单列表
	BlockFlag         uint64   //0->不永久封锁，>0->永久封锁
	UnBlockTime       uint64   //非永久封锁时的解封时间
}

// 编译好的eBPF程序路径
var elf = flag.String("elf", "ebpf_prog/xdp_fw.elf", "clang/llvm compiled binary file")

// 存储要阻止的IPv4地址
var ipList ipAddressList

const config_path = "./xdpfw.json"

func main() {
	configFile, err1 := os.Open(config_path)
	if err1 != nil {
		fatalError("Failed to open config file: %v", err1)
	}
	defer configFile.Close()

	configData, err2 := io.ReadAll(configFile)
	if err2 != nil {
		fatalError("Failed to read config file: %v", err2)
	}
	var config Config
	err3 := json.Unmarshal(configData, &config)
	if err3 != nil {
		fatalError("Failed to unmarshal config: %v", err3)
	}
	fmt.Printf("InterfaceName: %s\n", config.InterfaceName)
	fmt.Printf("PPS: %d\n", config.PPS)
	fmt.Printf("BPS: %d\n", config.BPS)
	fmt.Printf("Ipv4BlacklistTemp: %v\n", config.Ipv4BlacklistTemp)
	fmt.Printf("Ipv4BlacklistPerm: %v\n", config.Ipv4BlacklistPerm)
	fmt.Printf("BlockFlag: %d\n", config.BlockFlag)
	fmt.Printf("UnBlockTime: %d\n", config.UnBlockTime)
	//创建eBPF系统实例，并加载编译好的eBPF程序。
	bpf := goebpf.NewDefaultEbpfSystem()
	err4 := bpf.LoadElf(*elf)
	if err4 != nil {
		fatalError("LoadElf() failed: %v", err4)
	}
	printBpfInfo(bpf)
	config_pps := bpf.GetMapByName("config_pps")
	config_bps := bpf.GetMapByName("config_bps")
	if config_pps == nil {
		fatalError("eBPF map 'config_pps' not found")
	} else {
		err := config_pps.Insert(1, config.PPS)
		if err != nil {
			fatalError("Unable to Insert into eBPF map: %v", err)
		}
	}
	if config_bps == nil {
		fatalError("eBPF map 'config_bps' not found")
	} else {
		err := config_bps.Insert(2, config.BPS)
		if err != nil {
			fatalError("Unable to Insert into eBPF map: %v", err)
		}
	}
	block_time := bpf.GetMapByName("block_flag")
	un_block_time := bpf.GetMapByName("unblock_time")
	if block_time == nil {
		fatalError("eBPF map 'block_time' not found")
	} else {
		err := block_time.Insert(3, config.BlockFlag)
		if err != nil {
			fatalError("Unable to Insert into eBPF map: %v", err)
		}
	}
	if un_block_time == nil {
		fatalError("eBPF map 'un_block_time' not found")
	} else {
		err := un_block_time.Insert(4, config.UnBlockTime)
		if err != nil {
			fatalError("Unable to Insert into eBPF map: %v", err)
		}
	}
	ip_blacklist_t := bpf.GetMapByName("ip_blacklist_t")
	if ip_blacklist_t == nil {
		fatalError("eBPF map 'ip_blacklist_t' not found")
	}
	for i, s := range config.Ipv4BlacklistTemp {
		ipu32, erri := ipToUint32(s)
		if erri != nil {
			fmt.Println(erri)
			continue
		}
		err := ip_blacklist_t.Insert(ipu32, 1)
		if err != nil {
			fatalError("Unable to Insert into eBPF map: %v", err)
		}
		ipList = append(ipList, s)
		fmt.Printf("Ipv4BlacklistTemp[%d]: %d----%x\n", i, ipu32, ipu32)
	}
	ip_blacklist_p := bpf.GetMapByName("ip_blacklist_p")
	if ip_blacklist_p == nil {
		fatalError("eBPF map 'ip_blacklist_p' not found")
	}
	for i, s := range config.Ipv4BlacklistPerm {
		ipu32, erri := ipToUint32(s)
		if erri != nil {
			fmt.Println(erri)
			continue
		}
		err := ip_blacklist_p.Insert(ipu32, 1)
		if err != nil {

			fatalError("Unable to Insert into eBPF map: %v", err)
		}
		ipList = append(ipList, s)
		fmt.Printf("Ipv4BlacklistPerm[%d]: %d----%x\n", i, ipu32, ipu32)
	}
	// Get XDP program. Name simply matches function from xdp_fw.c:
	//      int firewall(struct xdp_md *ctx) {
	xdp := bpf.GetProgramByName("firewall")
	if xdp == nil {
		fatalError("Program 'firewall' not found.")
	}

	// Populate eBPF map with IPv4 addresses to block
	fmt.Println("Blacklisting IPv4 addresses...")

	// Load XDP program into kernel
	err6 := xdp.Load()
	if err6 != nil {
		fatalError("xdp.Load(): %v", err6)
	}

	// Attach to interface
	err7 := xdp.Attach(config.InterfaceName)
	if err7 != nil {
		fatalError("xdp.Attach(): %v", err7)
	}
	//用于确保在函数返回之前调用xdp.Detach函数
	defer xdp.Detach()

	fmt.Println("XDP program successfully loaded and attached.")
	fmt.Println()

	//创建一个定时器，每秒触发一次。
	//进入一个无限循环，同时等待定时器通道和中断信号通道。
	//当中断信号通道接收到信号时，打印退出消息并退出程序。

	//ticker := time.NewTicker(1 * time.Second)
	//defer ticker.Stop()

	// 用户输入通道
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("按'e'键修改配置，按'q'键退出程序\n")
		text, _ := reader.ReadString('\n')
		text = strings.Trim(text, " \n")
		if text == "e" || text == "E" {
			fmt.Printf("1. PPS 2. BPS 3. Ipv4BlacklistTemp 4. Ipv4BlacklistPerm 5. BlockFlag 6. UnBlockTime 7. Quit")
			fmt.Printf("\n请输入要修改的项:")
			newInput, _ := reader.ReadString('\n')
			newInput = strings.Trim(newInput, " \n")
			num, err := strconv.Atoi(newInput)
			fmt.Printf("您选择修改的项是: %d\n", num)
			if err != nil {
				fmt.Println("输入格式错误")
				continue
			}
			if num == 1 {
				fmt.Printf("当前PPS是%d，要修改吗？(y/n)", config.PPS)
				newInput, _ := reader.ReadString('\n')
				if newInput == "y\n" || newInput == "Y\n" {
					fmt.Print("请输入新的PPS: ")
					newInput, _ := reader.ReadString('\n')
					newInput = strings.TrimSpace(newInput)
					newPPS, err := strconv.Atoi(newInput)
					if err != nil {
						fmt.Println("输入错误")
						continue
					}
					config.PPS = uint64(newPPS)
					err2 := config_pps.Insert(1, config.PPS)
					if err2 != nil {
						fatalError("Unable to Insert into eBPF map: %v", err2)
					}
					fmt.Print("修改成功\n")
					/*
						value, err := config_pps.Lookup(1)
						if err != nil {
							fatalError("Unable to Lookup into eBPF map: %v", err)
						}
						fmt.Printf("NEW_PPS: %d\n", value)
					*/
				}
			} else if num == 2 {
				fmt.Printf("当前BPS是%d，要修改吗？(y/n)", config.BPS)
				newInput, _ := reader.ReadString('\n')
				if newInput == "y\n" || newInput == "Y\n" {
					fmt.Print("请输入新的BPS: ")
					newInput, _ := reader.ReadString('\n')
					newInput = strings.TrimSpace(newInput)
					fmt.Print("newInput: ", newInput)
					newBPS, err := strconv.Atoi(newInput)
					if err != nil {
						fmt.Println("输入错误")
						continue
					}
					config.BPS = uint64(newBPS)
					err2 := config_bps.Insert(2, config.BPS)
					if err2 != nil {
						fatalError("Unable to Insert into eBPF map: %v", err2)
					}
					fmt.Print("修改成功\n")
				}
			} else if num == 3 {
				fmt.Printf("当前Ipv4BlacklistTemp(临时ip地址黑名单)的内容是:\n")
				firstKey, err1 := ip_blacklist_t.GetNextKey(nil)
				if err1 != nil {
					fmt.Printf("空\n")
				}
				currentKey := firstKey
				cnt := 0
				for currentKey != nil {
					// 使用当前键获取下一个键
					nextKey, err_2 := ip_blacklist_t.GetNextKey(currentKey)
					fmt.Printf("%d:%d(十进制)\t%x(十六进制)", cnt, currentKey, currentKey)
					if err_2 != nil {
						break
					}
					// 更新当前键为下一个键，继续遍历
					currentKey = nextKey
				}
				fmt.Printf("\n请输入要删除的ip地址(点分十进制,形如192.168.1.1)(多个ip地址间以空格分隔)(不输入请直接按回车):")
				newInput2, _ := reader.ReadString('\n')
				newInput2 = strings.TrimSpace(newInput2)
				newIpList2 := strings.Split(newInput2, " ")
				for _, s := range newIpList2 {
					ipu32, erri := ipToUint32(s)
					if erri != nil {
						fmt.Println(erri)
						continue
					}
					err2 := ip_blacklist_t.Delete(ipu32)
					if err2 != nil {
						fatalError("Unable to Delete from eBPF map: %v", err)
					}
				}
				fmt.Printf("\n请输入要添加的ip地址(点分十进制,形如192.168.1.1)(多个ip地址间以空格分隔)(不输入请直接按回车):")
				newInput, _ := reader.ReadString('\n')
				newInput = strings.TrimSpace(newInput)
				newIpList := strings.Split(newInput, " ")
				for _, s := range newIpList {
					ipu32, erri := ipToUint32(s)
					if erri != nil {
						fmt.Println(erri)
						continue
					}
					err2 := ip_blacklist_t.Insert(ipu32, 1)
					if err2 != nil {
						fatalError("Unable to Insert into eBPF map: %v", err)
					}
				}
				fmt.Print("修改成功\n")
			} else if num == 4 {
				fmt.Printf("当前Ipv4BlacklistPerm(永久ip地址黑名单)的内容是:\n")
				firstKey, err1 := ip_blacklist_p.GetNextKey(nil)
				if err1 != nil {
					fmt.Printf("空\n")
				}
				currentKey := firstKey
				cnt := 0
				for currentKey != nil {
					// 使用当前键获取下一个键
					nextKey, err_2 := ip_blacklist_p.GetNextKey(currentKey)
					fmt.Printf("%d:%d(十进制)\t%x(十六进制)", cnt, currentKey, currentKey)
					if err_2 != nil {
						break
					}
					// 更新当前键为下一个键，继续遍历
					currentKey = nextKey
				}
				fmt.Printf("\n请输入要删除的ip地址(点分十进制,形如192.168.1.1)(多个ip地址间以空格分隔)(不输入请直接按回车):")
				newInput2, _ := reader.ReadString('\n')
				newInput2 = strings.TrimSpace(newInput2)
				newIpList2 := strings.Split(newInput2, " ")
				for _, s := range newIpList2 {
					ipu32, erri := ipToUint32(s)
					if erri != nil {
						fmt.Println(erri)
						continue
					}
					err2 := ip_blacklist_p.Delete(ipu32)
					if err2 != nil {
						fatalError("Unable to Delete from eBPF map: %v", err)
					}
				}
				fmt.Printf("\n请输入要添加的ip地址(点分十进制,形如192.168.1.1)(多个ip地址间以空格分隔)(不输入请直接按回车):")
				newInput, _ := reader.ReadString('\n')
				newInput = strings.TrimSpace(newInput)
				newIpList := strings.Split(newInput, " ")
				for _, s := range newIpList {
					ipu32, erri := ipToUint32(s)
					if erri != nil {
						fmt.Println(erri)
						continue
					}
					err2 := ip_blacklist_p.Insert(ipu32, 1)
					if err2 != nil {
						fatalError("Unable to Insert into eBPF map: %v", err)
					}
				}
				fmt.Print("修改成功\n")
			} else if num == 5 {
				fmt.Printf("当前BlockFlag是%d，要修改吗？(y/n)", config.BlockFlag)
				newInput, _ := reader.ReadString('\n')
				if newInput == "y\n" || newInput == "Y\n" {
					fmt.Print("\n请输入新的BlockFlag: ")
					newInput, _ := reader.ReadString('\n')
					newBlockFlag, err := strconv.Atoi(newInput)
					if err != nil {
						fmt.Println("\n输入错误")
						continue
					}
					config.BlockFlag = uint64(newBlockFlag)
					err2 := block_time.Update(3, config.BlockFlag)
					if err2 != nil {
						fatalError("Unable to Insert into eBPF map: %v", err2)
					}
					fmt.Print("修改成功\n")
				}
			} else if num == 6 {
				fmt.Printf("当前UnBlockTime是%d，要修改吗？(y/n)", config.UnBlockTime)
				newInput, _ := reader.ReadString('\n')
				if newInput == "y\n" || newInput == "Y\n" {
					fmt.Print("请输入新的UnBlockTime: ")
					newInput, _ := reader.ReadString('\n')
					newUnBlockTime, err := strconv.Atoi(newInput)
					if err != nil {
						fmt.Println("输入错误")
						continue
					}
					config.UnBlockTime = uint64(newUnBlockTime)
					err2 := un_block_time.Update(4, config.UnBlockTime)
					if err2 != nil {
						fatalError("Unable to Insert into eBPF map: %v", err2)
					}
					fmt.Print("修改成功\n")
				}
			}
		} else if text == "q" || text == "Q" {
			fmt.Println("\nDetaching program and exit")
			return
		}
	}

}

func fatalError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// Implements flag.Value
func (i *ipAddressList) String() string {
	return fmt.Sprintf("%+v", *i)
}

func printBpfInfo(bpf goebpf.System) {
	fmt.Println("Maps:")
	for _, item := range bpf.GetMaps() {
		fmt.Printf("\t%s: %v, Fd %v\n", item.GetName(), item.GetType(), item.GetFd())
	}
	fmt.Println("\nPrograms:")
	for _, prog := range bpf.GetPrograms() {
		fmt.Printf("\t%s: %v, size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense(),
		)

	}
	fmt.Println()
}

func ipToUint32(ip string) (uint32, error) {
	addr := net.ParseIP(ip)
	if addr == nil {
		return 0, fmt.Errorf(ip + "无效的IP地址")
	}
	ipv4 := addr.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf(ip + "不是IPv4地址")
	}
	return uint32(ipv4[0])<<24 + uint32(ipv4[1])<<16 + uint32(ipv4[2])<<8 + uint32(ipv4[3]), nil
}
