package pinglistener

import (
    "fmt"
    "log"
    "net"
    "time"
    "sync"

    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"
    "golang.org/x/net/ipv6"
)

const (
	// timeSliceLength  = 8
	protocolICMP     = 1
    protocolIPv6ICMP = 58
)

var (
	ipv4Proto = map[string]string{"ip": "ip4:icmp", "udp": "udp4"}
	ipv6Proto = map[string]string{"ip": "ip6:ipv6-icmp", "udp": "udp6"}
)

// type IcmpData struct {
// 	Bytes   []byte
// 	Tracker int64
// }

type packet struct {
    T time.Time
    Addr  string
	Bytes  []byte
	Nbytes int
}

type PingListener struct {
    ipv4 bool
    status bool
    ipaddr *net.IPAddr
    addr string
    network string  

	// OnRecv is called when Pinger receives and filtered a packet
	OnRecv func(*packet)

	// stop chan bool
	done chan bool
}

func bytesToTime(b []byte) time.Time {
	var nsec int64
	for i := uint8(0); i < 8; i++ {
		nsec += int64(b[i]) << ((7 - i) * 8)
	}
	return time.Unix(nsec/1000000000, nsec%1000000000)
}

func isIPv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}

func isIPv6(ip net.IP) bool {
	return len(ip) == net.IPv6len
}

func (p *PingListener) SetIPAddr(ipaddr *net.IPAddr) {
	var ipv4 bool
	if isIPv4(ipaddr.IP) {
		ipv4 = true
	} else if isIPv6(ipaddr.IP) {
		ipv4 = false
	}

	p.ipaddr = ipaddr
	p.addr = ipaddr.String()
	p.ipv4 = ipv4
}

// network can be "ip"  or "udp"
func NewPingListener(addr string, network string)(*PingListener, error){
   	ipaddr, err := net.ResolveIPAddr("ip", addr)
	if err != nil {
		return nil, err
	}

	var ipv4 bool
	if isIPv4(ipaddr.IP) {
		ipv4 = true
	} else if isIPv6(ipaddr.IP) {
		ipv4 = false
    }
    return &PingListener{
        ipv4: ipv4,
        status: false,
        ipaddr: ipaddr,
        addr: addr,
        network: network,
        // stop chan bool
        // done: make(chan bool),
    }, nil
}

func (p *PingListener) listen(netProto string, source string) *icmp.PacketConn {
	conn, err := icmp.ListenPacket(netProto, source)
	if err != nil {
		log.Printf("Error listening for ICMP packets: %s\n", err.Error())
		close(p.done)
		return nil
	}
	return conn
}


func (p *PingListener) Status() bool{
    return p.status
}

func (p *PingListener) Start() {
    if p.status {
        log.Println("PingListener is running")
        return
    }
    p.status = true
    p.done = make(chan bool)

	var conn *icmp.PacketConn
	if p.ipv4 {
		if conn = p.listen(ipv4Proto[p.network], p.addr); conn == nil {
			return
		}
	} else {
		if conn = p.listen(ipv6Proto[p.network], p.addr); conn == nil {
			return
		}
	}
	defer conn.Close()
	// defer p.finish()

	var wg sync.WaitGroup
	recv := make(chan *packet, 5)
	defer close(recv)
	wg.Add(1)
	go p.recvICMP(conn, recv, &wg)


	for {
		select {
        case <-p.done:
            p.status = false
			wg.Wait()
			return
		case r := <-recv:
			err := p.filterPacket(r)
			if err != nil {
				log.Println("FATAL: ", err.Error())
			}
		}
	}
}

func (p *PingListener) Stop() {
    if p.status {
        close(p.done)
        p.status = false
    }
}


func (p *PingListener) recvICMP(
	conn *icmp.PacketConn,
	recv chan<- *packet,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	for {
		select {
		case <-p.done:
			return
		default:
			bytes := make([]byte, 512)
			conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
			n, addr, err := conn.ReadFrom(bytes)
			if err != nil {
				if neterr, ok := err.(*net.OpError); ok {
					if neterr.Timeout() {
						// Read timeout
						continue
					} else {
                        log.Printf("Ping listener %v recv exception: %v", p.addr, neterr)
                        continue
					}
				}
			}
			recv <- &packet{T: time.Now() ,Addr: addr.String() ,Bytes: bytes[:n], Nbytes: n}
		}
	}
}


func (p *PingListener) filterPacket(recv *packet) error {
	var bytes []byte
	var proto int
	if p.ipv4 {
		if p.network == "ip" {
			bytes = ipv4Payload(recv.Bytes)
		} else {
			bytes = recv.Bytes
		}
		proto = protocolICMP
	} else {
		bytes = recv.Bytes
		proto = protocolIPv6ICMP
	}

	var m *icmp.Message
	var err error
	if m, err = icmp.ParseMessage(proto, bytes); err != nil {
		return fmt.Errorf("Error parsing icmp message")
	}
	log.Printf("%+v, \n", m)
	if m.Type == ipv4.ICMPTypeEchoReply || m.Type == ipv6.ICMPTypeEchoReply {
        // Is an echo reply, ignore it
		return nil
    }

	switch pkt := m.Body.(type) {
	case *icmp.Echo:
        // Don't know how to unmarshal this kind of data.
		// data := IcmpData{}
		// err := json.Unmarshal(m.Body.(*icmp.Echo).Data, &data)
		// if err != nil {
        //     log.Println(err)
		// } else {
		//     Rtt := time.Since(bytesToTime(data.Bytes))
        // }
		// Seq := pkt.Seq
		// log.Printf("echo: rtt %v  seq %v, tracker %v\n", Rtt, Seq, data.Tracker)

	case *icmp.DefaultMessageBody:

    // Don't know how to unmarshal this kind of data.
		// data := IcmpData{}
		// log.Printf("default msg: body %v \n", m.Body.(*icmp.DefaultMessageBody))
		// err := json.Unmarshal(m.Body.(*icmp.DefaultMessageBody).Data, &data)
		// if err != nil {
        //     log.Println(*(*string)(unsafe.Pointer(&m.Body.(*icmp.DefaultMessageBody).Data)))
		// } else {
        //     Rtt := time.Since(bytesToTime(data.Bytes))
        //     log.Printf("default msg: rtt %v  seq %v, \n", Rtt,  data.Tracker)
        // }

  case *icmp.DstUnreach:
        return nil
	case *icmp.TimeExceeded:
        // log.Printf("time exceed %v", m.Body.(*icmp.TimeExceeded))
        return nil
        
	default:
		return fmt.Errorf("Error, invalid ICMP echo reply. Body type: %T, %s",
			pkt, pkt)
    }

    handler := p.OnRecv
    if handler != nil {
        handler(recv)
    }
	return nil
}


func ipv4Payload(b []byte) []byte {
	if len(b) < ipv4.HeaderLen {
		return b
	}
    hdrlen := int(b[0]&0x0f) << 2
    if hdrlen < len(b) {
	    return b[hdrlen:]
    } else {
        return b
    }
}
