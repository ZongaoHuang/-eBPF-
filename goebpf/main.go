package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dropbox/goebpf"
)

type ipAddressList []string

type Config struct {
	InterfaceName     string
	PPS               uint64   //每秒ip数据包数限制
	BPS               uint64   //每秒ip字节数限制
	Ipv4BlacklistTemp []string //用户初始自定义的可动态封锁的黑名单列表
	Ipv4BlacklistPerm []string //永久封锁的黑名单列表
	BlockFlag         uint64   //0->不永久封锁，1->永久封锁
	UnBlockTime       uint64   //非永久封锁时的解封时间
	SYNPS             uint64   //每秒SYN数据包数限制
	UDPPS             uint64   //每秒UDP数据包数限制
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
	fmt.Printf("SYNPS: %d\n", config.SYNPS)
	fmt.Printf("UDPPS: %d\n", config.UDPPS)
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
	config_syn_count := bpf.GetMapByName("config_syn")
	config_udp_count := bpf.GetMapByName("config_udp")
	if config_syn_count == nil {
		fatalError("eBPF map 'config_syn_count' not found")
	} else {
		err := config_syn_count.Insert(5, config.SYNPS)
		if err != nil {
			fatalError("Unable to Insert into eBPF map: %v", err)
		}
	}
	if config_udp_count == nil {
		fatalError("eBPF map 'config_udp_count' not found")
	} else {
		err := config_udp_count.Insert(6, config.UDPPS)
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
	//      int firewall(struct xdp_md *ctx) {
	xdp := bpf.GetProgramByName("firewall")
	if xdp == nil {
		fatalError("Program 'firewall' not found.")
	}

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

	fmt.Print("\nXDP program successfully loaded and attached.\n")

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
		text = strings.TrimSpace(text)
		if text == "e" || text == "E" {
			fmt.Printf("1. PPS(每秒数据包数)\t2. BPS(每秒字节数)\t3. Ipv4BlacklistTemp(临时ip黑名单)\n4. Ipv4BlacklistPerm(永久ip黑名单)\t5. BlockFlag(是否永久封禁临时黑名单中的ip,0表示不永久，1表示永久)\n6. UnBlockTime(不永久封禁时,临时ip的解封时间(秒))\t7. Print(打印信息到文件)\n8.SYNPS(每秒SYN请求数)\t9.UDPPS(每秒UDP包数)\t10. Quit(退出修改)\n")
			fmt.Printf("\n请输入要修改的项:")
			newInput, _ := reader.ReadString('\n')
			newInput = strings.TrimSpace(newInput)
			num, err := strconv.Atoi(newInput)
			//fmt.Printf("您选择修改的项是: %d\n", num)
			if err != nil {
				fmt.Println("输入格式错误")
				continue
			}
			if num == 1 {
				fmt.Printf("当前PPS是%d，要修改吗？(y/n)", config.PPS)
				newInput, _ := reader.ReadString('\n')
				newInput = strings.TrimSpace(newInput)
				if newInput == "y" || newInput == "Y" {
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
					fmt.Print("\n修改成功\n")
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
				newInput = strings.TrimSpace(newInput)
				if newInput == "y" || newInput == "Y" {
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
					fmt.Print("\n修改成功\n")
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
					keyUint32 := binary.LittleEndian.Uint32(currentKey)
					fmt.Printf("%d:%s\t", cnt, ipToDecimal(keyUint32))
					if err_2 != nil {
						break
					}
					cnt++
					if cnt%3 == 0 {
						fmt.Print("\n")
					}
					// 更新当前键为下一个键，继续遍历
					currentKey = nextKey
				}
				fmt.Print("\n请输入要删除的ip地址(点分十进制,形如192.168.1.1)(多个ip地址间以空格分隔)(不输入请直接按回车):")
				newInput2, _ := reader.ReadString('\n')
				newInput2 = strings.TrimSpace(newInput2)
				newIpList2 := strings.Split(newInput2, " ")
				for _, s := range newIpList2 {
					ipu32, erri := ipToUint32(s)
					if erri != nil {
						fmt.Println(erri)
						continue
					}

					_, err1 := ip_blacklist_t.Lookup(ipu32)
					if err1 != nil {
						fmt.Printf("\n临时黑名单中不存在该ip:%s，不能删除\n", s)
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
					_, err1 := ip_blacklist_t.Lookup(ipu32)
					if err1 == nil {
						fmt.Printf("\n临时黑名单中存在该ip:%s，不用添加\n", s)
						continue
					}
					err2 := ip_blacklist_t.Insert(ipu32, 1)
					if err2 != nil {
						fmt.Print("\nUnable to Insert into eBPF map: %v\n", err)
					}
				}
				fmt.Print("\n修改成功\n")
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
					keyUint32 := binary.LittleEndian.Uint32(currentKey)
					fmt.Printf("%d:%s\t", cnt, ipToDecimal(keyUint32))
					if err_2 != nil {
						break
					}
					cnt++
					if cnt%3 == 0 {
						fmt.Print("\n")
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
					_, err1 := ip_blacklist_p.Lookup(ipu32)
					if err1 != nil {
						fmt.Printf("\n永久黑名单中不存在该ip:%s，不能删除\n", s)
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
					_, err1 := ip_blacklist_p.Lookup(ipu32)
					if err1 == nil {
						fmt.Printf("\n永久黑名单中存在该ip:%s，不用添加\n", s)
						continue
					}
					err2 := ip_blacklist_p.Insert(ipu32, 1)
					if err2 != nil {
						fmt.Print("Unable to Insert into eBPF map: %v", err)
					}
				}
				fmt.Print("\n修改成功\n")
			} else if num == 5 {
				fmt.Printf("当前BlockFlag是%d，要修改吗？(y/n)", config.BlockFlag)
				newInput, _ := reader.ReadString('\n')
				newInput = strings.TrimSpace(newInput)
				if newInput == "y" || newInput == "Y" {
					fmt.Print("\n请输入新的BlockFlag: ")
					newInput, _ := reader.ReadString('\n')
					newInput = strings.TrimSpace(newInput)
					newBlockFlag, err := strconv.Atoi(newInput)
					if err != nil {
						fmt.Println("\n输入错误")
						continue
					}
					config.BlockFlag = uint64(newBlockFlag)
					err2 := block_time.Insert(3, config.BlockFlag)
					if err2 != nil {
						fatalError("Unable to Insert into eBPF map: %v", err2)
					}
					fmt.Print("\n修改成功\n")
				}
			} else if num == 6 {
				fmt.Printf("当前UnBlockTime是%d，要修改吗？(y/n)", config.UnBlockTime)
				newInput, _ := reader.ReadString('\n')
				newInput = strings.TrimSpace(newInput)
				if newInput == "y" || newInput == "Y" {
					fmt.Print("请输入新的UnBlockTime: ")
					newInput, _ := reader.ReadString('\n')
					newInput = strings.TrimSpace(newInput)
					newUnBlockTime, err := strconv.Atoi(newInput)
					if err != nil {
						fmt.Println("输入错误")
						continue
					}
					config.UnBlockTime = uint64(newUnBlockTime)
					err2 := un_block_time.Insert(4, config.UnBlockTime)
					if err2 != nil {
						fatalError("Unable to Insert into eBPF map: %v", err2)
					}
					fmt.Print("\n修改成功\n")
				}
			} else if num == 7 {
				fmt.Print("请输入要打印的文件名(不输入请直接按回车,并采用默认文件名xdp_fw.log):")
				newInput, _ := reader.ReadString('\n')
				newInput = strings.TrimSpace(newInput)
				if newInput == "" {
					newInput = "xdp_fw.log"
				}
				file, err := os.OpenFile(newInput, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
				if err != nil {
					fmt.Printf("\n打开文件失败:%s\n", newInput)
					continue
				}
				defer file.Close()
				fmt.Println("开始打印")
				//获取临时黑名单
				fmt.Fprintf(file, "\n系统时间:%s\n", time.Now().Format("2006-01-02 15:04:05"))
				fmt.Fprintf(file, "临时黑名单:\n")
				firstKey, err1 := ip_blacklist_t.GetNextKey(nil)
				if err1 != nil {
					fmt.Fprintf(file, "空\n")
				}
				currentKey := firstKey
				cnt := 0
				for currentKey != nil {
					// 使用当前键获取下一个键
					nextKey, err_2 := ip_blacklist_t.GetNextKey(currentKey)
					keyUint32 := binary.LittleEndian.Uint32(currentKey)
					fmt.Fprintf(file, "%d:%s\t", cnt, ipToDecimal(keyUint32))
					if err_2 != nil {
						break
					}
					cnt++
					if cnt%3 == 0 {
						fmt.Fprintf(file, "\n")
					}
					// 更新当前键为下一个键，继续遍历
					currentKey = nextKey
				}
				//获取永久黑名单
				fmt.Fprintf(file, "\n永久黑名单:\n")
				firstKey, err1 = ip_blacklist_p.GetNextKey(nil)
				if err1 != nil {
					fmt.Fprintf(file, "空\n")
				}
				currentKey = firstKey
				cnt = 0
				for currentKey != nil {
					// 使用当前键获取下一个键
					nextKey, err_2 := ip_blacklist_p.GetNextKey(currentKey)
					keyUint32 := binary.LittleEndian.Uint32(currentKey)
					fmt.Fprintf(file, "%d:%s\t", cnt, ipToDecimal(keyUint32))
					if err_2 != nil {
						break
					}
					currentKey = nextKey
					cnt++
					if cnt%3 == 0 {
						fmt.Fprintf(file, "\n")
					}
				}
				fmt.Fprintf(file, "\n")
				fmt.Println("打印成功")
			} else if num == 8 {
				fmt.Printf("当前SYNPS是%d，要修改吗？(y/n)", config.SYNPS)
				newInput, _ := reader.ReadString('\n')
				newInput = strings.TrimSpace(newInput)
				if newInput == "y" || newInput == "Y" {
					fmt.Print("请输入新的SYNPS: ")
					newInput, _ := reader.ReadString('\n')
					newInput = strings.TrimSpace(newInput)
					newSYNPS, err := strconv.Atoi(newInput)
					if err != nil {
						fmt.Println("输入错误")
						continue
					}
					config.SYNPS = uint64(newSYNPS)
					err2 := config_syn_count.Insert(5, config.SYNPS)
					if err2 != nil {
						fatalError("Unable to Insert into eBPF map: %v", err2)
					}
					fmt.Print("\n修改成功\n")
				}
			} else if num == 9 {
				fmt.Printf("当前UDPPS是%d，要修改吗？(y/n)", config.UDPPS)
				newInput, _ := reader.ReadString('\n')
				newInput = strings.TrimSpace(newInput)
				if newInput == "y" || newInput == "Y" {
					fmt.Print("请输入新的UDPPS: ")
					newInput, _ := reader.ReadString('\n')
					newInput = strings.TrimSpace(newInput)
					newUDPPS, err := strconv.Atoi(newInput)
					if err != nil {
						fmt.Println("输入错误")
						continue
					}
					config.UDPPS = uint64(newUDPPS)
					err2 := config_udp_count.Insert(6, config.UDPPS)
					if err2 != nil {
						fatalError("Unable to Insert into eBPF map: %v", err2)
					}
					fmt.Print("\n修改成功\n")
				}
			}
		} else if text == "q" || text == "Q" {
			fmt.Print("\nDetaching program and exit\n")
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
		return 0, fmt.Errorf(ip + "是无效的IP地址")
	}
	ipv4 := addr.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf(ip + "不是IPv4地址")
	}
	return uint32(ipv4[0])<<24 + uint32(ipv4[1])<<16 + uint32(ipv4[2])<<8 + uint32(ipv4[3]), nil
}

func ipToDecimal(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip>>24, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF)
}
