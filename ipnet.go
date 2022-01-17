// Author: Justin P. Rohrer (rohrej@gmail.com)
// Date: 14 Aug. 2019
// Convenience functions for working with IP addresses, prefixes, and subnets

package ipnet

import (
  "os"
  "net"
  "log"
  "bufio"
  "strings"
  "math/big"
  "encoding/binary"
  "github.com/infobloxopen/go-trees/iptree"
)

type Set map[uint64]struct{}

var (
  Ipver int
  Lowbits uint64
  nets *iptree.Tree
  blocklist *iptree.Tree
  allones *big.Int
  //maxthreads int
  Empty struct{}
  debug bool
)

func init() {
  allones = big.NewInt(0)
  allones.SetString("0xffffffffffffffffffffffffffffffff", 0)
  nets = iptree.NewTree()
  blocklist = iptree.NewTree()
  //maxthreads = runtime.NumCPU()
  debug = false
}

func (i Set) Has(v uint64) bool {
  _, ok := i[v]
  return ok
}

func Four2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func FourMask2int(nm net.IPMask) uint32 {
	if len(nm) == 16 {
		return binary.BigEndian.Uint32(nm[12:16])
	}
	return binary.BigEndian.Uint32(nm)
}

func Int2four(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func Six2int(IPv6Addr net.IP) *big.Int {
  IPv6Int := big.NewInt(0)
  IPv6Int.SetBytes(IPv6Addr)
  return IPv6Int
}

func SixMask2int(IPv6Mask net.IPMask) *big.Int {
  IPv6Int := big.NewInt(0)
  IPv6Int.SetBytes(IPv6Mask)
  return IPv6Int
}

func Int2six(intipv6 *big.Int) net.IP {
  return net.IP(intipv6.Bytes())
}

func Ipv6tosixty4(IPv6Addr net.IP) uint64 {
	return binary.BigEndian.Uint64(IPv6Addr[0:8])
}

func Ip2sixty4(IpAddr net.IP) uint64 {
	if Ipver == 4 {
		return uint64(Four2int(IpAddr))
	}
	return Ipv6tosixty4(IpAddr)
}

func Sixty4toIPv6(highbits uint64) net.IP {
	ip := make(net.IP, 16)
	binary.BigEndian.PutUint64(ip[0:8], highbits)
	binary.BigEndian.PutUint64(ip[8:16], Lowbits)
	return ip
}

func Sixty4toIP(highbits uint64) net.IP {
	if Ipver == 4 {
		return Int2four(uint32(highbits))
	}
  return Sixty4toIPv6(highbits)
}

func Broadcast(n *net.IPNet) net.IP {
  if Ipver == 4 {
    mask := FourMask2int(n.Mask)
    network := Four2int(n.IP)
    broadcast := (network & mask) | (mask ^ 0xffffffff)
    return Int2four(broadcast)
  }
  mask := SixMask2int(n.Mask)
  network := Six2int(n.IP)
  broadcast := big.NewInt(0)
  broadcast.And(network, mask)
  broadcast.Or(broadcast, mask.Xor(mask, allones))
  return Int2six(broadcast)
}

func Bounds(n *net.IPNet) (uint64, uint64) {
  if Ipver == 4 {
    return uint64(Four2int(n.IP)), uint64(Four2int(Broadcast(n)))
  } else {
    return Ipv6tosixty4(n.IP), Ipv6tosixty4(Broadcast(n))
  }
}

func Contains(n *net.IPNet) bool {
  if _, present := nets.GetByNet(n); present {
    return true
  }
  return false
}

func GetBlockByIP(ip net.IP) (interface{}, bool) {
  return blocklist.GetByIP(ip)
}

func Add(n *net.IPNet) bool {
  if ! Contains(n) {
    nets, _ = nets.DeleteByNet(n)
    nets.InplaceInsertNet(n, true)
    return true
  }
  return false
}

func Enumerate() chan iptree.Pair {
  return nets.Enumerate()
}

func MakeCoveringTree(bgptableName string) {
  log.Println("Creating BGP tree from: ", bgptableName)
	handle, err := os.Open(bgptableName)
	if err != nil {
		log.Fatalln(err)
	}
	defer handle.Close()
	reader := bufio.NewReader(handle)
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			break
		}
		cidrip := strings.Fields(string(line))[0]
		if Ipver == 4 && string(cidrip[0]) == ">" {
			cidrip = cidrip[1:]
		} else if Ipver == 4 || string(cidrip[0]) == ":" {
			continue
		}
		_, subnet, prsErr := net.ParseCIDR(cidrip)
		if prsErr != nil {
			log.Println("Parse error:", prsErr)
			continue
		}
    blocked := false
    _, blocked = blocklist.GetByNet(subnet)
    if !blocked {
		  Add(subnet)
    }
	}
}

func MakeTree(bgptableName string) {
	log.Println("Creating BGP tree from: ", bgptableName)
	handle, err := os.Open(bgptableName)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	reader := bufio.NewReader(handle)
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			break
		}
		_, subnet, _ := net.ParseCIDR(strings.Fields(string(line))[0])
    blocked := false
    _, blocked = blocklist.GetByNet(subnet)
    if !blocked {
		  nets.InplaceInsertNet(subnet, true)
    }
	}
}

func MakeBlockTree(blocklistName string) {
	log.Println("Creating blocklist tree from: ", blocklistName)
	if blocklistName != "" {
		handle, err := os.Open(blocklistName)
		if err != nil {
			log.Fatalln(err)
		}
		defer handle.Close()
		reader := bufio.NewReader(handle)
		for {
			line, _, err := reader.ReadLine()
			if err != nil {
				break
			}
			_, subnet, _ := net.ParseCIDR(strings.Fields(string(line))[0])
			blocklist.InplaceInsertNet(subnet, true)
		}
	}
}
