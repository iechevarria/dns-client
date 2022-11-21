package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
)

/*
A		1 a host address
NS		2 an authoritative name server
MD		3 a mail destination (Obsolete - use MX)
MF		4 a mail forwarder (Obsolete - use MX)
CNAME	5 the canonical name for an alias
SOA		6 marks the start of a zone of authority
MB		7 a mailbox domain name (EXPERIMENTAL)
MG		8 a mail group member (EXPERIMENTAL)
MR		9 a mail rename domain name (EXPERIMENTAL)
NULL	10 a null RR (EXPERIMENTAL)
WKS		11 a well known service description
PTR		12 a domain name pointer
HINFO	13 host information
MINFO	14 mailbox or mail list information
MX		15 mail exchange
TXT		16 text strings
*/
const (
	A = iota + 1
	NS
	MD
	MF
	CNAME
	SOA
	MB
	MG
	MR
	NULL
	WKS
	PTR
	HINFO
	MINFO
	MX
	TXT
)

/*
IN		1 the Internet
CS		2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
CH		3 the CHAOS class
HS		4 Hesiod [Dyer 87]
*/
const (
	IN = iota + 1
	CS
	CH
	HS
)

/*
       	                        1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
type DnsFlags uint16

func (f DnsFlags) QR() uint16 {
	return uint16(f >> 15)
}
func (f DnsFlags) OpCode() uint16 {
	return uint16(f >> 11 & 0b1111)
}
func (f DnsFlags) AA() uint16 {
	return uint16(f >> 10 & 0b1)
}
func (f DnsFlags) TC() uint16 {
	return uint16(f >> 9 & 0b1)
}
func (f DnsFlags) RD() uint16 {
	return uint16(f >> 8 & 0b1)
}
func (f DnsFlags) RA() uint16 {
	return uint16(f >> 7 & 0b1)
}
func (f DnsFlags) Z() uint16 {
	return uint16(f >> 4 & 0b111)
}
func (f DnsFlags) RCode() uint16 {
	return uint16(f & 0b1111)
}
func (f DnsFlags) String() string {
	return fmt.Sprintf("QR: %d, OpCode: %d, AA: %d, TC: %d, RD: %d, RA: %d, Z: %d, RCode: %d", f.QR(), f.OpCode(), f.AA(), f.TC(), f.RD(), f.RA(), f.Z(), f.RCode())
}

/*
      	                        1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   | QR = 0, Opcode = 0, AA = 0, TC = 0, RD = 1, RA = 0, Z = 0, RCODE = 0
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    | number of entries in the question section = 1
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    | number of resource records in the answer section = 0
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    | number of name server resource records in the authority records section = 0
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    | number of resource records in the additional records section = 1
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
type DnsHeader struct {
	Id      uint16
	Flags   DnsFlags
	QdCount uint16
	AnCount uint16
	NsCount uint16
	ArCount uint16
}

func (h DnsHeader) String() string {
	return fmt.Sprintf("Id: %d, Flags: [%s], QdCount: %d, AnCount: %d, NsCount: %d, ArCount: %d", h.Id, h.Flags, h.QdCount, h.AnCount, h.NsCount, h.ArCount)
}

/*
QNAME not included in this struct since it has variable length

			     			    1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QTYPE                     | 0x0001 = A
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QCLASS                    | 0x0001 = IN
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
type DnsQuestion struct {
	QType  uint16
	QClass uint16
}

/*
  							    1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                      |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   RDLENGTH                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|

Name and RData not included in this struct since they have variable length
*/
type DnsResourceRecord struct {
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
}

func (r DnsResourceRecord) String() string {
	return fmt.Sprintf("Type: %d, Class: %d, TTL: %d, RDLength: %d", r.Type, r.Class, r.TTL, r.RDLength)
}

func ReadName(buf *bytes.Buffer) (string, error) {
	var name string
	var length uint8
	var err error
	for {
		length, err = buf.ReadByte()
		if err != nil {
			return "", err
		}
		if length == 0 {
			break
		}
		name += string(buf.Next(int(length)))
		name += "."
	}
	return name, nil
}

func main() {
	//    4    d    o    c    s    6    g    o    o    g   l     e    3    c   o    m   end
	// 0x04 0x64 0x6f 0x63 0x73 0x06 0x67 0x6f 0x6f 0x67 0x6c 0x65 0x03 0x63 0x6f 0x6d 0x00
	// request_qname := [...]byte{0x04, 0x64, 0x6f, 0x63, 0x73, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00}

	var url = "docs.google.com"

	// Construct qname
	var qnameSlice []byte
	for _, a := range strings.Split(url, ".") {
		qnameSlice = append(qnameSlice, byte(len(a)))
		qnameSlice = append(qnameSlice, []byte(a)...)
	}
	qnameSlice = append(qnameSlice, 0)

	// Construct header
	requestHeader := DnsHeader{
		Id:      12345,
		Flags:   0x0100,
		QdCount: 1,
		AnCount: 0,
		NsCount: 0,
		ArCount: 0,
	}
	question := DnsQuestion{
		QType:  A,
		QClass: IN,
	}

	fmt.Println(requestHeader)

	// Construct query
	var query bytes.Buffer
	binary.Write(&query, binary.BigEndian, requestHeader)
	binary.Write(&query, binary.BigEndian, qnameSlice)
	binary.Write(&query, binary.BigEndian, question)

	// Send query
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		panic(err)
	}
	err = syscall.Bind(sock, &syscall.SockaddrInet4{Port: 53})
	if err != nil {
		panic(err)
	}
	err = syscall.Sendto(sock, query.Bytes(), 0, &syscall.SockaddrInet4{Port: 53, Addr: [4]byte{8, 8, 8, 8}})
	if err != nil {
		panic(err)
	}

	// Recv response
	var response [512]byte
	n, _, err := syscall.Recvfrom(sock, response[:], 0)
	if err != nil {
		panic(err)
	}

	// Response header
	responseBuf := bytes.NewBuffer(response[:n])
	var responseHeader DnsHeader
	binary.Read(responseBuf, binary.BigEndian, &responseHeader)
	fmt.Println(responseHeader)

	// Validate response header
	if responseHeader.Id != requestHeader.Id {
		panic(fmt.Sprintf("response id %d does not match request id %d", responseHeader.Id, requestHeader.Id))
	}
	if responseHeader.QdCount != requestHeader.QdCount {
		panic(fmt.Sprintf("response qdcount %d does not match request qdcount %d", responseHeader.QdCount, requestHeader.QdCount))
	}
	if responseHeader.AnCount == 0 {
		panic("response ancount is 0")
	}
	if responseHeader.NsCount != requestHeader.NsCount {
		panic(fmt.Sprintf("response nscount %d does not match request nscount %d", responseHeader.NsCount, requestHeader.NsCount))
	}
	if responseHeader.ArCount != requestHeader.ArCount {
		panic(fmt.Sprintf("response arcount %d does not match request arcount %d", responseHeader.ArCount, requestHeader.ArCount))
	}
	if responseHeader.Flags.QR() != 1 {
		panic("response qr is not 1 (response)")
	}
	if responseHeader.Flags.OpCode() != 0 {
		panic("response opcode is not 0 (standard query)")
	}
	if responseHeader.Flags.AA() != 0 {
		panic("response aa is not 0 (not authoritative)")
	}
	if responseHeader.Flags.TC() != 0 {
		panic("response tc is not 0 (not truncated)")
	}
	if responseHeader.Flags.RD() != requestHeader.Flags.RD() {
		panic(fmt.Sprintf("response rd %d does not match request rd %d (recursion desired)", responseHeader.Flags.RD(), requestHeader.Flags.RD()))
	}
	if responseHeader.Flags.RA() != 1 {
		panic("response ra is not 1 (recursion available)")
	}
	if responseHeader.Flags.Z() != 0 {
		panic("response z is not 0")
	}
	if responseHeader.Flags.RCode() != 0 {
		panic("response rcode is not 0 (no error)")
	}

	name, err := ReadName(responseBuf)
	if err != nil {
		panic("error reading name: " + err.Error())
	}
	fmt.Println(name)

	var responseResourceRecord DnsResourceRecord
	binary.Read(responseBuf, binary.BigEndian, &responseResourceRecord)
	fmt.Println(responseResourceRecord)

	if responseResourceRecord.Type != question.QType {
		panic(fmt.Sprintf("response type %d does not match question type %d", responseResourceRecord.Type, question.QType))
	}
	if responseResourceRecord.Class != question.QClass {
		panic(fmt.Sprintf("response class %d does not match question class %d", responseResourceRecord.Class, question.QClass))
	}

	fmt.Println(responseBuf)

	err = syscall.Close(sock)
	if err != nil {
		panic(err)
	}

	// fmt.Println(sock)
}
