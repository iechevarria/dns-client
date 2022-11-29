package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
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

type DnsHeader struct {
	Id      uint16
	Flags   DnsFlags
	QdCount uint16
	AnCount uint16
	NsCount uint16
	ArCount uint16
}

func (h DnsHeader) String() string {
	return fmt.Sprintf("Id: %d, Flags: { %s }, QdCount: %d, AnCount: %d, NsCount: %d, ArCount: %d", h.Id, h.Flags, h.QdCount, h.AnCount, h.NsCount, h.ArCount)
}

type DnsQuestion struct {
	QName  string
	QType  uint16
	QClass uint16
}

func (q DnsQuestion) String() string {
	return fmt.Sprintf("QName: %s, QType: %d, QClass: %d", q.QName, q.QType, q.QClass)
}

type DnsRequest struct {
	Header    DnsHeader
	Questions []DnsQuestion
}

func (r DnsRequest) String() string {
	var qStr string
	for _, q := range r.Questions {
		qStr += fmt.Sprintf("\n  { %s }", q)
	}
	return fmt.Sprintf("Header: { %s }, Questions: { %s }", r.Header, qStr)
}

type DnsResourceRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      int32
	RDLength uint16
	RData    []byte
}

func (r DnsResourceRecord) String() string {
	switch r.Type {
	case CNAME:
		reader := bytes.NewReader(r.RData)
		cName, err := ReadName(reader)
		if err != nil {
			cName = "error"
		}
		return fmt.Sprintf("Name: %s, Type: %d, Class: %d, TTL: %d, RDLength: %d, RData: %s", r.Name, r.Type, r.Class, r.TTL, r.RDLength, cName)
	default:
		return fmt.Sprintf("Name: %s, Type: %d, Class: %d, TTL: %d, RDLength: %d, RData: %v", r.Name, r.Type, r.Class, r.TTL, r.RDLength, r.RData)
	}
}

type DnsResponse struct {
	Header    DnsHeader
	Questions []DnsQuestion
	Answers   []DnsResourceRecord
}

func (r DnsResponse) String() string {
	var qStr string
	var aStr string
	for _, q := range r.Questions {
		qStr += fmt.Sprintf("\n  { %s }", q)
	}
	for _, a := range r.Answers {
		aStr += fmt.Sprintf("\n  { %s }", a)
	}
	return fmt.Sprintf("Header: { %s }\nQuestions: [%s\n]\nAnswers: [%s\n]", r.Header, qStr, aStr)
}

func ReadName(r *bytes.Reader) (string, error) {
	// Should I be declaring stuff here?
	var name string
	var length uint8
	var pointer uint16
	var nextByte byte
	var err error
	for {
		length, err = r.ReadByte()
		if err != nil {
			return "", err
		}

		// Handle compressed name
		// 0xc0 = 0b11000000
		if length&0xc0 == 0xc0 {
			// Get pointer
			nextByte, err = r.ReadByte()
			if err != nil {
				return "", err
			}
			pointer = uint16(length&0b00111111)<<8 | uint16(nextByte)

			// Save old reader position
			pos, err := r.Seek(0, io.SeekCurrent)
			if err != nil {
				return "", err
			}

			// Seek to pointer and read name
			_, err = r.Seek(int64(pointer), io.SeekStart)
			if err != nil {
				return "", err
			}
			name, err = ReadName(r)
			if err != nil {
				return "", err
			}

			// Restore reader position
			_, err = r.Seek(pos, io.SeekStart)
			if err != nil {
				return "", err
			}
			return name, nil
		}

		if length == 0 {
			// Removes last dot. This is hacky and should be done better :)
			name = name[:len(name)-1]
			break
		}

		// Reads label. Is there not a better way to do this?
		label := make([]byte, length)
		_, err = r.Read(label)
		if err != nil {
			return "", err
		}
		name += string(label) + "."
	}
	return name, nil
}

func ReadQuestion(r *bytes.Reader) (DnsQuestion, error) {
	// Stupid hack to get around "non-name" thing if I try to set q.QName directly
	var QName string
	var q DnsQuestion
	QName, err := ReadName(r)
	if err != nil {
		return q, err
	}
	q.QName = QName

	binary.Read(r, binary.BigEndian, &q.QType)
	binary.Read(r, binary.BigEndian, &q.QClass)
	return q, nil
}

func ReadResourceRecord(r *bytes.Reader) (DnsResourceRecord, error) {
	var res DnsResourceRecord
	name, err := ReadName(r)
	if err != nil {
		return res, err
	}
	res.Name = name
	binary.Read(r, binary.BigEndian, &res.Type)
	binary.Read(r, binary.BigEndian, &res.Class)
	binary.Read(r, binary.BigEndian, &res.TTL)
	binary.Read(r, binary.BigEndian, &res.RDLength)
	res.RData = make([]byte, res.RDLength)
	_, err = r.Read(res.RData)
	if err != nil {
		return res, err
	}
	return res, nil
}

func SerializeName(name string) []byte {
	var buf bytes.Buffer
	for _, label := range strings.Split(name, ".") {
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0)
	return buf.Bytes()
}

func SerializeQuestion(buf *bytes.Buffer, question DnsQuestion) {
	binary.Write(buf, binary.BigEndian, SerializeName(question.QName))
	binary.Write(buf, binary.BigEndian, question.QType)
	binary.Write(buf, binary.BigEndian, question.QClass)
}

func main() {
	// var url = "docs.google.com"
	var urls = []string{"init.push.apple.com"}

	var request DnsRequest
	request.Header = DnsHeader{
		Id:      12345,
		Flags:   0x0100,
		QdCount: 1,
		AnCount: 0,
		NsCount: 0,
		ArCount: 0,
	}
	for _, url := range urls {
		request.Questions = append(request.Questions, DnsQuestion{
			QName:  url,
			QType:  1,
			QClass: 1,
		})
	}

	// Serialize query
	var reqBuf bytes.Buffer
	// Write header
	binary.Write(&reqBuf, binary.BigEndian, request.Header)
	// Write questions
	for _, q := range request.Questions {
		SerializeQuestion(&reqBuf, q)
	}

	// Send reqBuf
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		panic(err)
	}
	err = syscall.Bind(sock, &syscall.SockaddrInet4{Port: 53})
	if err != nil {
		panic(err)
	}
	err = syscall.Sendto(sock, reqBuf.Bytes(), 0, &syscall.SockaddrInet4{Port: 53, Addr: [4]byte{8, 8, 8, 8}})
	if err != nil {
		panic(err)
	}

	// Recv response
	buf := make([]byte, 512)
	n, _, err := syscall.Recvfrom(sock, buf, 0)
	if err != nil {
		panic(err)
	}

	// Read response header
	responseReader := bytes.NewReader(buf[:n])
	var response DnsResponse
	binary.Read(responseReader, binary.BigEndian, &response.Header)

	// Validate response header
	if response.Header.Id != request.Header.Id {
		panic(fmt.Sprintf("response id %d does not match request id %d", response.Header.Id, request.Header.Id))
	}
	if response.Header.QdCount != request.Header.QdCount {
		panic(fmt.Sprintf("response qdcount %d does not match request qdcount %d", response.Header.QdCount, request.Header.QdCount))
	}
	if response.Header.AnCount == 0 {
		panic("response ancount is 0")
	}
	if response.Header.NsCount != request.Header.NsCount {
		panic(fmt.Sprintf("response nscount %d does not match request nscount %d", response.Header.NsCount, request.Header.NsCount))
	}
	if response.Header.ArCount != request.Header.ArCount {
		panic(fmt.Sprintf("response arcount %d does not match request arcount %d", response.Header.ArCount, request.Header.ArCount))
	}
	if response.Header.Flags.QR() != 1 {
		panic("response qr is not 1 (response)")
	}
	if response.Header.Flags.OpCode() != 0 {
		panic("response opcode is not 0 (standard query)")
	}
	if response.Header.Flags.AA() != 0 {
		panic("response aa is not 0 (not authoritative)")
	}
	if response.Header.Flags.TC() != 0 {
		panic("response tc is not 0 (not truncated)")
	}
	if response.Header.Flags.RD() != request.Header.Flags.RD() {
		panic(fmt.Sprintf("response rd %d does not match request rd %d (recursion desired)", response.Header.Flags.RD(), request.Header.Flags.RD()))
	}
	if response.Header.Flags.RA() != 1 {
		panic("response ra is not 1 (recursion available)")
	}
	if response.Header.Flags.Z() != 0 {
		panic("response z is not 0")
	}
	if response.Header.Flags.RCode() != 0 {
		panic("response rcode is not 0 (no error)")
	}

	// Read response questions
	for i := 0; i < int(response.Header.QdCount); i++ {
		question, err := ReadQuestion(responseReader)
		if err != nil {
			panic(err)
		}
		response.Questions = append(response.Questions, question)
	}

	// Read response answers
	for i := 0; i < int(response.Header.AnCount); i++ {
		answer, err := ReadResourceRecord(responseReader)
		if err != nil {
			panic(err)
		}
		response.Answers = append(response.Answers, answer)
	}

	fmt.Println(response)

	err = syscall.Close(sock)
	if err != nil {
		panic(err)
	}
}
