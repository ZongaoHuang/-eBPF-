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

type ARPEntry struct {
	Ip  string `json:"Ip"`  // 匹配 JSON 中的 "Ip"
	Mac string `json:"Mac"` // 匹配 JSON 中的 "Mac"
}

type Config struct {
	InterfaceName     string     `json:"InterfaceName"`
	PPS               uint64     `json:"PPS"`               //每秒ip数据包数限制
	BPS               uint64     `json:"BPS"`               //每秒ip字节数限制
	Ipv4BlacklistTemp []string   `json:"Ipv4BlacklistTemp"` //用户初始自定义的可动态封锁的黑名单列表
	Ipv4BlacklistPerm []string   `json:"Ipv4BlacklistPerm"` //永久封锁的黑名单列表
	BlockFlag         uint64     `json:"BlockFlag"`         //0->不永久封锁，非0->永久封锁
	UnBlockTime       uint64     `json:"UnBlockTime"`       //非永久封锁时的解封时间
	SYNPS             uint64     `json:"SYNPS"`             //每秒SYN数据包数限制
	UDPPS             uint64     `json:"UDPPS"`             //每秒UDP数据包数限制
	ArpFlag           uint64     `json:"ArpFlag"`           //0->不开启ip-mac映射表，非0->开启
	ArpTable          []ARPEntry `json:"ArpTable"`          // ARP 条目切片
}

// 编译好的eBPF程序路径
var elf = flag.String("elf", "ebpf_prog/xdp_fw.elf", "clang/llvm compiled binary file")

const config_path = "./xdpfw.json"

func main() {

	configFile, err1 := os.Open(config_path)
	if err1 != nil {
		fatalError("无法打开配置文件: %v", err1)
	}
	defer configFile.Close()

	configData, err2 := io.ReadAll(configFile)
	if err2 != nil {
		fatalError("无法读取配置文件: %v", err2)
	}
	var config Config
	err3 := json.Unmarshal(configData, &config)
	if err3 != nil {
		fatalError("无法解析配置文件: %v", err3)
	}
	fmt.Printf("\n配置文件内容如下:\n")
	fmt.Printf("\nInterfaceName: %s\n", config.InterfaceName)
	fmt.Printf("PPS: %d\n", config.PPS)
	fmt.Printf("BPS: %d\n", config.BPS)
	fmt.Printf("Ipv4BlacklistTemp: %v\n", config.Ipv4BlacklistTemp)
	fmt.Printf("Ipv4BlacklistPerm: %v\n", config.Ipv4BlacklistPerm)
	fmt.Printf("BlockFlag: %d\n", config.BlockFlag)
	fmt.Printf("UnBlockTime: %d\n", config.UnBlockTime)
	fmt.Printf("SYNPS: %d\n", config.SYNPS)
	fmt.Printf("UDPPS: %d\n", config.UDPPS)
	fmt.Printf("ArpFlag: %d\n", config.ArpFlag)
	fmt.Println("ARP Table Entries:")
	for i, entry := range config.ArpTable {
		fmt.Printf("%3d:\tIP: %15s\tMAC: %s\n", i, entry.Ip, entry.Mac)
	}
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
		fatalError("eBPF map 类型的 'config_pps' 找不到")
	} else {
		err := config_pps.Insert(1, config.PPS)
		if err != nil {
			fatalError("无法插入 eBPF map: %v", err)
		}
	}
	if config_bps == nil {
		fatalError("eBPF map 类型的 'config_bps' 找不到")
	} else {
		err := config_bps.Insert(2, config.BPS)
		if err != nil {
			fatalError("无法插入 eBPF map: %v", err)
		}
	}
	block_time := bpf.GetMapByName("block_flag")
	un_block_time := bpf.GetMapByName("unblock_time")
	if block_time == nil {
		fatalError("eBPF map 类型的 'block_time' 找不到")
	} else {
		err := block_time.Insert(3, config.BlockFlag)
		if err != nil {
			fatalError("无法插入 eBPF map: %v", err)
		}
	}
	if un_block_time == nil {
		fatalError("eBPF map 类型的 'un_block_time' 找不到")
	} else {
		err := un_block_time.Insert(4, config.UnBlockTime)
		if err != nil {
			fatalError("无法插入 eBPF map: %v", err)
		}
	}
	config_syn_count := bpf.GetMapByName("config_syn")
	config_udp_count := bpf.GetMapByName("config_udp")
	if config_syn_count == nil {
		fatalError("eBPF map 类型的 'config_syn_count' 找不到")
	} else {
		err := config_syn_count.Insert(5, config.SYNPS)
		if err != nil {
			fatalError("无法插入 eBPF map: %v", err)
		}
	}
	if config_udp_count == nil {
		fatalError("eBPF map 类型的 'config_udp_count' 找不到")
	} else {
		err := config_udp_count.Insert(6, config.UDPPS)
		if err != nil {
			fatalError("无法插入 eBPF map: %v", err)
		}
	}
	ip_blacklist_t := bpf.GetMapByName("ip_blacklist_t")
	if ip_blacklist_t == nil {
		fatalError("eBPF map 类型的 'ip_blacklist_t' 找不到")
	}
	for i, s := range config.Ipv4BlacklistTemp {
		ipu32, erri := ipToUint32(s)
		if erri != nil {
			fmt.Println(erri)
			continue
		}
		err := ip_blacklist_t.Insert(ipu32, 1)
		if err != nil {
			fatalError("无法插入 eBPF map: %v", err)
		}
		fmt.Printf("Ipv4BlacklistTemp[%d]: %d----%x\n", i, ipu32, ipu32)
	}
	ip_blacklist_p := bpf.GetMapByName("ip_blacklist_p")
	if ip_blacklist_p == nil {
		fatalError("eBPF map 类型的 'ip_blacklist_p' 找不到")
	}
	for i, s := range config.Ipv4BlacklistPerm {
		ipu32, erri := ipToUint32(s)
		if erri != nil {
			fmt.Println(erri)
			continue
		}
		err := ip_blacklist_p.Insert(ipu32, 1)
		if err != nil {

			fatalError("无法插入 eBPF map: %v", err)
		}
		//fmt.Printf("Ipv4BlacklistPerm[%d]: %d----%x\n", i, ipu32, ipu32)
	}
	arp_flag := bpf.GetMapByName("arp_flag")
	if arp_flag == nil {
		fatalError("eBPF map 类型的 'arp_flag' 找不到")
	} else {
		err := arp_flag.Insert(7, config.ArpFlag)
		if err != nil {
			fatalError("无法插入 eBPF map: %v", err)
		}
	}
	arp_table := bpf.GetMapByName("arp_table")
	if arp_table == nil {
		fatalError("eBPF map 类型的 'arp_table' 找不到")
	}
	for _, entry := range config.ArpTable {
		ipu32, erri := ipToUint32(entry.Ip)
		if erri != nil {
			fmt.Println(erri)
			continue
		}
		mac, err := macToUint48(entry.Mac)
		if err != nil {
			fmt.Println(err)
			continue
		}
		err = arp_table.Insert(ipu32, mac)
		if err != nil {
			fatalError("无法插入 eBPF map: %v", err)
		}
	}
	drop_cnt := bpf.GetMapByName("drop_cnt")
	if drop_cnt == nil {
		fatalError("eBPF map 类型的 'drop_cnt' 找不到")
	} else {
		// 初始化 drop_cnt 为 0
		value := uint64(0)
		err := drop_cnt.Insert(8, value)
		if err != nil {
			fatalError("数据无法插入 eBPF map: %v", err)
		}
	}
	pass_cnt := bpf.GetMapByName("pass_cnt")
	if pass_cnt == nil {
		fatalError("eBPF map 类型的 'pass_cnt' 找不到")
	} else {
		// 初始化 pass_cnt 为 0
		value := uint64(0)
		err := pass_cnt.Insert(9, value)
		if err != nil {
			fatalError("数据无法插入 eBPF map: %v", err)
		}
	}
	/*
		wrong_cnt := bpf.GetMapByName("wrong_cnt")
		if wrong_cnt == nil {
			fatalError("eBPF map 类型的 'wrong_cnt' 找不到")
		} else {
			// 初始化 wrong_cnt 为 0
			value := uint64(0)
			err := wrong_cnt.Insert(10, value)
			if err != nil {
				fatalError("数据无法插入 eBPF map: %v", err)
			}
		}
		temp_cnt := bpf.GetMapByName("temp_cnt")
		if temp_cnt == nil {
			fatalError("eBPF map 类型的 'temp_cnt' 找不到")
		} else {
			// 初始化 temp_cnt 为 0
			value := uint64(0)
			err := temp_cnt.Insert(11, value)
			if err != nil {
				fatalError("数据无法插入 eBPF map: %v", err)
			}
		}
		now_cnt := bpf.GetMapByName("now_cnt")
		if now_cnt == nil {
			fatalError("eBPF map 类型的 'now_cnt' 找不到")
		} else {
			// 初始化 now_cnt 为 0
			value := uint64(0)
			err := now_cnt.Insert(12, value)
			if err != nil {
				fatalError("数据无法插入 eBPF map: %v", err)
			}
		}
		next_cnt := bpf.GetMapByName("next_cnt")
		if next_cnt == nil {
			fatalError("eBPF map 类型的 'next_cnt' 找不到")
		} else {
			// 初始化 next_cnt 为 0
			value := uint64(0)
			err := next_cnt.Insert(13, value)
			if err != nil {
				fatalError("数据无法插入 eBPF map: %v", err)
			}
		}
		btime_cnt := bpf.GetMapByName("btime_cnt")
		if btime_cnt == nil {
			fatalError("eBPF map 类型的 'btime_cnt' 找不到")
		} else {
			// 初始化 btime_cnt 为 0
			value := uint64(0)
			err := btime_cnt.Insert(14, value)
			if err != nil {
				fatalError("数据无法插入 eBPF map: %v", err)
			}
		}
	*/
	//获取名为'firewall'的XDP程序
	xdp := bpf.GetProgramByName("firewall")
	if xdp == nil {
		fatalError("程序'firewall'找不到!")
	}
	//加载XDP程序
	err6 := xdp.Load()
	if err6 != nil {
		fatalError("xdp.Load(): %v", err6)
	}

	//将XDP程序附加到指定的网络接口上
	err7 := xdp.Attach(config.InterfaceName)
	if err7 != nil {
		fatalError("xdp.Attach(): %v", err7)
	}
	//用于确保在函数返回之前调用xdp.Detach函数
	defer xdp.Detach()

	fmt.Print("\nXDP program successfully loaded and attached.\n")

	// 用户输入通道
	reader := bufio.NewReader(os.Stdin)
	longString := "\n1. PPS(每秒数据包数)                  2. BPS(每秒字节数)                        3. Ipv4BlacklistTemp(临时ip黑名单)\n" +
		"4. Ipv4BlacklistPerm(永久ip黑名单)    5. BlockFlag(是否永久封禁临时黑名单中的ip,0表示不永久,1表示永久)\n" +
		"6. UnBlockTime(不永久封禁时,临时ip的解封时间(秒))                                7. Print(打印信息到文件)\n" +
		"8. SYNPS(每秒SYN请求数)               9. UDPPS(每秒UDP包数)                     10. ArpFlag(是否启用ip-mac映射表,0表示不启用,1表示启用)\n" +
		"11. ArpTable(配置ip-mac映射表)        12. Statistics(统计丢弃包和通过包数目)     13. Quit(退出修改)\n"
	for {
		fmt.Print("按'e'键修改配置，按'q'键退出程序\n")
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text == "e" || text == "E" {
			fmt.Printf(longString)
			fmt.Printf("\n请输入要修改的项:")
			newInput, _ := reader.ReadString('\n')
			newInput = strings.TrimSpace(newInput)
			if newInput == "" {
				continue
			}
			num, err := strconv.Atoi(newInput)
			if err != nil {
				fmt.Println("输入格式错误")
				continue
			}
			if num == 1 {
				fmt.Printf("当前PPS是%d,要修改吗?(y/n)", config.PPS)
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
					err2 := config_pps.Upsert(1, config.PPS)
					if err2 != nil {
						fatalError("Unable to Insert into eBPF map: %v", err2)
					}
				}
			} else if num == 2 {
				fmt.Printf("当前BPS是%d,要修改吗?(y/n)", config.BPS)
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
					err2 := config_bps.Upsert(2, config.BPS)
					if err2 != nil {
						fatalError("Unable to Insert into eBPF map: %v", err2)
					}
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
				newIpList2 := strings.Fields(newInput2)
				for _, s := range newIpList2 {
					ipu32, erri := ipToUint32(s)
					if erri != nil {
						fmt.Println(erri)
						continue
					}

					_, err1 := ip_blacklist_t.Lookup(ipu32)
					if err1 != nil {
						fmt.Printf("\n临时黑名单中不存在该ip:%s,不能删除\n", s)
						continue
					}

					err2 := ip_blacklist_t.Delete(ipu32)
					if err2 != nil {
						fatalError("Unable to Delete from eBPF map: %v", err)
					}
				}
				fmt.Printf("\n请输入要添加的ip地址(点分十进制,形如192.168.1.1)(多个ip地址间以空格分隔)(不输入请直接按回车):")
				newInput, _ := reader.ReadString('\n')
				newIpList := strings.Fields(newInput)
				for _, s := range newIpList {
					ipu32, erri := ipToUint32(s)
					if erri != nil {
						fmt.Println(erri)
						continue
					}
					_, err1 := ip_blacklist_t.Lookup(ipu32)
					if err1 == nil {
						fmt.Printf("\n临时黑名单中存在该ip:%s,不用添加\n", s)
						continue
					}
					err2 := ip_blacklist_t.Insert(ipu32, 1)
					if err2 != nil {
						fmt.Print("\nUnable to Insert into eBPF map: %v\n", err)
					}
				}
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
				newIpList2 := strings.Fields(newInput2)
				for _, s := range newIpList2 {
					ipu32, erri := ipToUint32(s)
					if erri != nil {
						fmt.Println(erri)
						continue
					}
					_, err1 := ip_blacklist_p.Lookup(ipu32)
					if err1 != nil {
						fmt.Printf("\n永久黑名单中不存在该ip:%s,不能删除\n", s)
						continue
					}
					err2 := ip_blacklist_p.Delete(ipu32)
					if err2 != nil {
						fatalError("Unable to Delete from eBPF map: %v", err)
					}
				}
				fmt.Printf("\n请输入要添加的ip地址(点分十进制,形如192.168.1.1)(多个ip地址间以空格分隔)(不输入请直接按回车):")
				newInput, _ := reader.ReadString('\n')
				newIpList := strings.Fields(newInput)
				for _, s := range newIpList {
					ipu32, erri := ipToUint32(s)
					if erri != nil {
						fmt.Println(erri)
						continue
					}
					_, err1 := ip_blacklist_p.Lookup(ipu32)
					if err1 == nil {
						fmt.Printf("\n永久黑名单中存在该ip:%s,不用添加\n", s)
						continue
					}
					err2 := ip_blacklist_p.Insert(ipu32, 1)
					if err2 != nil {
						fmt.Print("Unable to Insert into eBPF map: %v", err)
					}
				}
			} else if num == 5 {
				fmt.Printf("当前BlockFlag是%d,要修改吗?(y/n)", config.BlockFlag)
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
					err2 := block_time.Upsert(3, config.BlockFlag)
					if err2 != nil {
						fatalError("Unable to Insert into eBPF map: %v", err2)
					}
				}
			} else if num == 6 {
				fmt.Printf("当前UnBlockTime是%d,要修改吗?(y/n)", config.UnBlockTime)
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
					err2 := un_block_time.Upsert(4, config.UnBlockTime)
					if err2 != nil {
						fatalError("Unable to Insert into eBPF map: %v", err2)
					}
					/*
						tempNum, err_temp := un_block_time.Lookup(4)
						if err_temp != nil {
							fmt.Println("Unable to Lookup from eBPF map: %v", err_temp)
						}
						fmt.Printf("\n解封时间:%d\n", tempNum)
					*/
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
				//获取ip-mac映射表
				fmt.Fprintf(file, "\nIP-ARP映射表:\n")
				for i, entry := range config.ArpTable {
					fmt.Fprintf(file, "%d:\tIP: %s\tMAC: %s\n", i, entry.Ip, entry.Mac)
				}
				//获取统计信息
				dropCnt, errm := drop_cnt.Lookup(uint32(8))
				if errm != nil {
					fatalError("Unable to Lookup from eBPF map: %v", errm)
				}
				passCnt, errm2 := pass_cnt.Lookup(uint32(9))
				if errm2 != nil {
					fatalError("Unable to Lookup from eBPF map: %v", errm2)
				}
				/*
					wrongCnt, errm3 := wrong_cnt.Lookup(uint32(10))
					if errm3 != nil {
						fatalError("Unable to Lookup from eBPF map: %v", errm3)
					}
				*/
				var num_dropcnt uint64
				num_dropcnt = binary.LittleEndian.Uint64(dropCnt)
				var num_passcnt uint64
				num_passcnt = binary.LittleEndian.Uint64(passCnt)
				/*
					var num_wrongcnt uint64
					num_wrongcnt = binary.LittleEndian.Uint64(wrongCnt)
				*/
				fmt.Fprintf(file, "\n丢弃包数目:%d\n", num_dropcnt)
				fmt.Fprintf(file, "通过包数目:%d\n", num_passcnt)
				//fmt.Fprintf(file, "错误包数目:%d\n", num_wrongcnt)

				fmt.Fprintf(file, "\n")
				fmt.Println("打印成功")
			} else if num == 8 {
				fmt.Printf("当前SYNPS是%d,要修改吗?(y/n)", config.SYNPS)
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
					err2 := config_syn_count.Upsert(5, config.SYNPS)
					if err2 != nil {
						fatalError("Unable to Insert into eBPF map: %v", err2)
					}
				}
			} else if num == 9 {
				fmt.Printf("当前UDPPS是%d,要修改吗?(y/n)", config.UDPPS)
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
					err2 := config_udp_count.Upsert(6, config.UDPPS)
					if err2 != nil {
						fatalError("Unable to Insert into eBPF map: %v", err2)
					}
				}
			} else if num == 10 {
				fmt.Printf("当前ArpFlag是%d,要修改吗?(y/n)", config.ArpFlag)
				newInput, _ := reader.ReadString('\n')
				newInput = strings.TrimSpace(newInput)
				if newInput == "y" || newInput == "Y" {
					fmt.Print("请输入新的ArpFlag: ")
					newInput, _ := reader.ReadString('\n')
					newInput = strings.TrimSpace(newInput)
					newArpFlag, err := strconv.Atoi(newInput)
					if err != nil {
						fmt.Println("输入错误")
						continue
					}
					config.ArpFlag = uint64(newArpFlag)
					err2 := arp_flag.Upsert(7, config.ArpFlag)
					if err2 != nil {
						fatalError("Unable to Insert into eBPF map: %v", err2)
					}
				}
			} else if num == 11 {
				fmt.Printf("当前ArpTable(ip-mac映射表)的内容是:\n")
				for i, entry := range config.ArpTable {
					fmt.Printf("%3d:\tIP: %15s\tMAC: %s\n", i, entry.Ip, entry.Mac)
				}
				fmt.Printf("\n请输入要删除的ARP表项下标(不输入请直接按回车):")
				newInput2, _ := reader.ReadString('\n')
				newInput2 = strings.TrimSpace(newInput2)
				if newInput2 != "" {
					index, err := strconv.Atoi(newInput2)
					if err != nil {
						fmt.Println("输入错误")
						continue
					}
					if index < 0 || index >= len(config.ArpTable) {
						fmt.Println("下标越界")
						continue
					}
					config.ArpTable = append(config.ArpTable[:index], config.ArpTable[index+1:]...)
				}
				fmt.Printf("\n请输入要添加的ip-mac表项(不输入请直接按回车):")
				newInput, _ := reader.ReadString('\n')
				newInput = strings.TrimSpace(newInput)
				if newInput != "" {
					newArpEntry := strings.Fields(newInput)
					if len(newArpEntry) != 2 {
						fmt.Println("输入错误")
						continue
					}
					ipu32, erri := ipToUint32(newArpEntry[0])
					if erri != nil {
						fmt.Println(erri)
						continue
					}
					mac, err := macToUint48(newArpEntry[1])
					if err != nil {
						fmt.Println(err)
						continue
					}
					config.ArpTable = append(config.ArpTable, ARPEntry{Ip: newArpEntry[0], Mac: newArpEntry[1]})
					err2 := arp_table.Upsert(ipu32, mac)
					if err2 != nil {
						fatalError("Unable to Insert into eBPF map: %v", err2)
					}
				}
			} else if num == 12 {
				dropCnt, errm := drop_cnt.Lookup(uint32(8))
				if errm != nil {
					fatalError("Unable to Lookup from eBPF map: %v", errm)
				}
				passCnt, errm2 := pass_cnt.Lookup(uint32(9))
				if errm2 != nil {
					fatalError("Unable to Lookup from eBPF map: %v", errm2)
				}
				/*
					wrongCnt, errm3 := wrong_cnt.Lookup(uint32(10))
					if errm3 != nil {
						fatalError("Unable to Lookup from eBPF map: %v", errm3)
					}
					tempCnt, errm4 := temp_cnt.Lookup(uint32(11))
					if errm4 != nil {
						fatalError("Unable to Lookup from eBPF map: %v", errm4)
					}
					nowCnt, errm5 := now_cnt.Lookup(uint32(12))
					if errm5 != nil {
						fatalError("Unable to Lookup from eBPF map: %v", errm5)
					}
					nextCnt, errm6 := next_cnt.Lookup(uint32(13))
					if errm6 != nil {
						fatalError("Unable to Lookup from eBPF map: %v", errm6)
					}
					btimeCnt, errm7 := btime_cnt.Lookup(uint32(14))
					if errm7 != nil {
						fatalError("Unable to Lookup from eBPF map: %v", errm7)
					}
				*/
				var num_dropcnt uint64
				num_dropcnt = binary.LittleEndian.Uint64(dropCnt)
				var num_passcnt uint64
				num_passcnt = binary.LittleEndian.Uint64(passCnt)
				/*
					var num_wrongcnt uint64
					num_wrongcnt = binary.LittleEndian.Uint64(wrongCnt)
					var num_tempcnt uint64
					num_tempcnt = binary.LittleEndian.Uint64(tempCnt)
					var num_nowcnt uint64
					num_nowcnt = binary.LittleEndian.Uint64(nowCnt)
					var num_nextcnt uint64
					num_nextcnt = binary.LittleEndian.Uint64(nextCnt)
					var num_btimecnt uint64
					num_btimecnt = binary.LittleEndian.Uint64(btimeCnt)
				*/
				fmt.Printf("\n丢弃包数目:%d\n", num_dropcnt)
				fmt.Printf("通过包数目:%d\n", num_passcnt)
				/*
					fmt.Printf("错误包数目:%d\n", num_wrongcnt)
					fmt.Printf("解禁次数:%d\n", num_tempcnt)
					fmt.Printf("当前时间:%d\n", num_nowcnt)
					fmt.Printf("下一次时间:%d\n", num_nextcnt)
					fmt.Printf("封禁时间:%d\n", num_btimecnt)
				*/
			} else {
				fmt.Print("\n退出修改\n")
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

func macToUint48(macStr string) (uint64, error) {
	// 解析 MAC 地址字符串
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return 0, err
	}

	// 确保 MAC 地址长度为 6 字节
	if len(mac) != 6 {
		return 0, fmt.Errorf("invalid MAC address length: %d", len(mac))
	}

	// 将 MAC 地址的 6 字节转换为 48 位无符号数
	var macUint48 uint64
	for i := 0; i < 6; i++ {
		macUint48 = (macUint48 << 8) | uint64(mac[i])
	}

	return macUint48, nil
}
