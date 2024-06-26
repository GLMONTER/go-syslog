package rfc3164

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/GLMONTER/go-syslog/internal/syslogparser"
)

type Parser struct {
	buff     []byte
	cursor   int
	l        int
	priority syslogparser.Priority
	version  int
	header   header
	message  rfc3164message
	location *time.Location
	skipTag  bool
}

type header struct {
	timestamp time.Time
	hostname  string
}

type rfc3164message struct {
	tag     string
	content string
}

func NewParser(buff []byte) *Parser {
	return &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.Local,
	}
}

func (p *Parser) Location(location *time.Location) {
	p.location = location
}

const CiscoASATimestampRePattern = `^<\d+>:(?:(\w{3} \d{2} \d{2}:\d{2}:\d{2}(?: [A-Z]+)?) )?`

var ciscoASATimestampCaptureRe = regexp.MustCompile(CiscoASATimestampRePattern)

func (p *Parser) parseCiscoASAHeader() (header, error) {
	//Cisco ASA log, do a regex parse because it is not standard
	//example log : <166>:Apr 04 19:28:05 EDT: %ASA-session-6-106100: access-list outside_access_in permitted tcp outside/125.252.156.24(57274) -> NEX-DMZ/10.58.1.552(443) hit-cnt 1 first hit [0x8fca8d4d, 0xf3808cf3]
	match := ciscoASATimestampCaptureRe.FindStringSubmatch(string(p.buff))

	var timestamp string
	if match != nil && len(match) > 1 {
		timestamp = match[1]
	}

	if timestamp == "" {
		return header{
			timestamp: time.Now().UTC(),
			hostname:  "",
		}, nil
	}

	potentialLayouts := []string{
		"Jan 02 15:04:05 MST",
		"Jan 02 15:04:05",
	}

	var parsedTime time.Time
	var err error
	for _, layout := range potentialLayouts {
		parsedTime, err = time.ParseInLocation(layout, timestamp, p.location)
		if err == nil {
			fixTimestampIfNeeded(&parsedTime)
			break
		}
	}
	if err != nil {
		return header{}, fmt.Errorf("failed to parse time in Cisco ASA log: %v : %s", err, string(p.buff))
	}

	return header{
		timestamp: parsedTime,
		hostname:  "",
	}, nil
}

const SonicWallTimestampRePattern = `time="([^"]+)"`

var sonicWallTimestampCaptureRe = regexp.MustCompile(SonicWallTimestampRePattern)

const SonicWallHostnameRePattern = `fw=([0-9.]+)`

var sonicWallHostnameCaptureRe = regexp.MustCompile(SonicWallHostnameRePattern)

func (p *Parser) parseSonicWallHeader() (header, error) {
	//SonicOS log, do a regex parse because it is not standard
	//example log : <134>id=firewall sn=18B1690729A8 fw=10.205.123.15 time="2016-08-19 18:05:44" pri=1 c=32 m=609 msg="IPS Prevention Alert: DNS named version attempt" sid=143 ipscat=DNS ipspri=3 n=3 src=192.168.169.180:2907 dst=172.16.2.11:53
	timestampMatch := sonicWallTimestampCaptureRe.FindStringSubmatch(string(p.buff))
	var timestamp string
	if timestampMatch != nil && len(timestampMatch) > 1 {
		timestamp = timestampMatch[1]
	}

	hostnameMatch := sonicWallHostnameCaptureRe.FindStringSubmatch(string(p.buff))
	var hostname string
	if hostnameMatch != nil && len(hostnameMatch) > 1 {
		hostname = hostnameMatch[1]
	}

	potentialLayouts := []string{
		"2006-01-02 15:04:05 MST",
		"2006-01-02 15:04:05",
	}

	var parsedTime time.Time
	var err error
	for _, layout := range potentialLayouts {
		parsedTime, err = time.ParseInLocation(layout, timestamp, p.location)
		if err == nil {
			fixTimestampIfNeeded(&parsedTime)
			break
		}
	}
	if err != nil {
		return header{}, fmt.Errorf("failed to parse time in SonicWall log: %v : %s", err, string(p.buff))
	}

	return header{
		timestamp: parsedTime,
		hostname:  hostname,
	}, nil
}

const FortiOSTimestampRePattern = `eventtime=(\d+)`

var fortiOSTimestampCaptureRe = regexp.MustCompile(FortiOSTimestampRePattern)

const ciscoASATimestampCapture = `^<\d+>(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)`

var ciscoASATimestampRegexp = regexp.MustCompile(ciscoASATimestampCapture)

func (p *Parser) parseFortiOSHeader() (header, error) {
	//FortiOS log, do a regex parse because it is not standard
	//example log : <133>date=2024-01-31 time=13:36:54 devname="Y21FS1-101F" devid="FGUSI@#J%JI@I" eventtime=1706726214463347261 tz="-0500" logid="0000000011" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.2.2.30 srcport=50295 srcintf="almi-f5s" srcintfrole="undefined" dstip=10.3.1.1 dstport=90 dstintf="sr929" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=1583922 proto=3 action="start" policyid=905 policytype="policy" poluuid="fjkdsljjlk-5u39582305-573289527358" policyname="FIREWALL_POLICY" user="USER_ADMIN" authserver="AGENT_FO" dstuser="SVC_USER" centralnatid=5 service="TESTSERV" trandisp="noop" duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 rcvdpkt=0 vpntype="ipsecvpn" appcat="unscanned"
	match := fortiOSTimestampCaptureRe.FindStringSubmatch(string(p.buff))

	var timestamp string
	if match != nil && len(match) > 1 {
		timestamp = match[1]
	}

	timeNum, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return header{}, fmt.Errorf("failed to convert FortiOS event time to int: %v : %s", err, string(p.buff))
	}
	seconds := timeNum / int64(time.Second)
	nanoseconds := timeNum % int64(time.Second)
	parsedTime := time.Unix(seconds, nanoseconds)
	parsedTime = parsedTime.UTC()
	fixTimestampIfNeeded(&parsedTime)

	return header{
		timestamp: parsedTime,
		hostname:  "",
	}, nil
}

func (p *Parser) parseCiscoASA_RFC5424() (header, error) {
	//example log : <166>2018-06-27T12:17:46Z asa : %ASA-6-110002: Failed to locate egress interface for protocol from src interface :src IP/src port to dest IP/dest port
	match := ciscoASATimestampRegexp.FindStringSubmatch(string(p.buff))
	if match != nil && len(match) > 1 {
		timestampStr := match[1]
		var parsedTime time.Time
		var err error
		if strings.Contains(timestampStr, ".") {
			parsedTime, err = time.Parse(time.RFC3339Nano, timestampStr)
			if err != nil {
				return header{}, fmt.Errorf("failed to parse cisco ASA RFC5424 dot timestamp: %v", err)
			}
		} else {
			parsedTime, err = time.Parse(time.RFC3339, timestampStr)
			if err != nil {
				return header{}, fmt.Errorf("failed to parse cisco ASA RFC5424 timestamp: %v", err)
			}
		}

		fixTimestampIfNeeded(&parsedTime)
		return header{timestamp: parsedTime, hostname: ""}, nil
	}
	return header{}, fmt.Errorf("failed to parse cisco ASA RFC5424 timestamp: %v", "no match")
}

func (p *Parser) Parse() error {
	tcursor := p.cursor
	p.message = rfc3164message{content: string(p.buff)}
	p.header.timestamp = time.Now().UTC()

	pri, err := p.parsePriority()
	if err != nil {
		p.message = rfc3164message{content: string(p.buff)}
		// RFC3164 sec 4.3.3
		p.priority = syslogparser.Priority{P: 13, F: syslogparser.Facility{Value: 1}, S: syslogparser.Severity{Value: 5}}
		p.cursor = tcursor
		p.header.timestamp = time.Now().UTC()
		err = p.movePastContent()
		if err != syslogparser.ErrEOL {
			return err
		}
		return nil
	}

	var hdr header

	setDefaultFail := func() {
		// No tag processing should be done
		p.skipTag = true
		// Reset cursor for content read
		p.cursor = tcursor
	}

	tcursor = p.cursor
	var skipMessageParse bool
	hdr, err = p.parseHeader()
	if err == nil {
		p.cursor++
	} else if errors.Is(err, syslogparser.ErrSonicOSFormat) {
		skipMessageParse = true

		hdr, err = p.parseSonicWallHeader()
		if err != nil {
			setDefaultFail()
			return err
		}
	} else if errors.Is(err, syslogparser.ErrFortiOSFormat) {
		skipMessageParse = true

		hdr, err = p.parseFortiOSHeader()
		if err != nil {
			setDefaultFail()
			return err
		}
	} else if errors.Is(err, syslogparser.ErrCiscoASAFormat) {
		skipMessageParse = true

		hdr, err = p.parseCiscoASAHeader()
		if err != nil {
			setDefaultFail()
			return err
		}
	} else if errors.Is(err, syslogparser.ErrCiscoASARFC5424) {
		skipMessageParse = true

		hdr, err = p.parseCiscoASA_RFC5424()
		if err != nil {
			setDefaultFail()
			return err
		}
	} else {
		setDefaultFail()

		//we should error for this
		return err
	}

	if !skipMessageParse {
		msg, err := p.parsemessage()
		if !errors.Is(err, syslogparser.ErrEOL) {
			return err
		}
		p.message = msg
	} else {
		p.message = rfc3164message{
			tag:     "",
			content: string(p.buff),
		}
	}

	p.priority = pri
	p.version = syslogparser.NO_VERSION
	p.header = hdr

	return nil
}

func (p *Parser) Dump() syslogparser.LogParts {
	return syslogparser.LogParts{
		"timestamp": p.header.timestamp,
		"hostname":  p.header.hostname,
		"tag":       p.message.tag,
		"content":   p.message.content,
		"priority":  p.priority.P,
		"facility":  p.priority.F.Value,
		"severity":  p.priority.S.Value,
	}
}

func (p *Parser) parsePriority() (syslogparser.Priority, error) {
	return syslogparser.ParsePriority(p.buff, &p.cursor, p.l)
}

func (p *Parser) parseHeader() (header, error) {
	hdr := header{}
	var err error

	ts, err := p.parseTimestamp()
	if err != nil {
		return hdr, err
	}

	hostname, err := p.parseHostname()
	if err != nil {
		return hdr, err
	}

	hdr.timestamp = ts
	hdr.hostname = hostname

	return hdr, nil
}

func (p *Parser) parsemessage() (rfc3164message, error) {
	msg := rfc3164message{}
	var err error
	msg.content = string(p.buff)

	if !p.skipTag {
		tag, err := p.parseTag()
		if err != nil {
			return msg, err
		}
		msg.tag = tag
	}

	err = p.movePastContent()
	if err != syslogparser.ErrEOL {
		return msg, err
	}

	return msg, err
}

const ciscoASA_RFC5424Format = `^<\d+>(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)`

var ciscoASA_RFC5424Regexp = regexp.MustCompile(ciscoASA_RFC5424Format)

func checkCiscoASA_RFC5424(buff []byte) bool {
	if ciscoASA_RFC5424Regexp.MatchString(string(buff)) {
		return true
	}

	return false
}

const ciscoASAPriorityFormat = `<\d+>:`

var ciscoASARegexp = regexp.MustCompile(ciscoASAPriorityFormat)

// https://tools.ietf.org/html/rfc3164#section-4.1.2
func (p *Parser) parseTimestamp() (time.Time, error) {
	var ts time.Time
	var err error
	var tsFmtLen int
	var sub []byte

	tsFmts := []string{
		time.Stamp,
		time.RFC3339,
	}
	// if timestamps starts with numeric try formats with different order
	// it is more likely that timestamp is in RFC3339 format then
	if c := p.buff[p.cursor]; c > '0' && c < '9' {
		tsFmts = []string{
			time.RFC3339,
			time.Stamp,
		}
	}

	found := false
	for _, tsFmt := range tsFmts {
		tsFmtLen = len(tsFmt)

		if p.cursor+tsFmtLen > p.l {
			continue
		}

		sub = p.buff[p.cursor : tsFmtLen+p.cursor]
		ts, err = time.ParseInLocation(tsFmt, string(sub), p.location)
		if err == nil {
			found = true
			break
		}
	}

	if !found {
		p.cursor = len(time.Stamp)

		// XXX : If the timestamp is invalid we try to push the cursor one byte
		// XXX : further, in case it is a space
		if (p.cursor < p.l) && (p.buff[p.cursor] == ' ') {
			p.cursor++
		}

		//Cisco ASA firewalls have their priority/timestamp like <166>:Apr 04 19:28:05 EDT, lets use regex to detect it
		if ciscoASARegexp.MatchString(string(p.buff)) {
			return ts, syslogparser.ErrCiscoASAFormat
		}

		//sonicOS has their own syslog format documented here, we try and detect their timestamp format if we run into an error
		//https://www.sonicwall.com/techdocs/pdf/sonicos-6-5-1-log-events-reference-guide.pdf
		if strings.Contains(string(p.buff), `time="`) {
			return ts, syslogparser.ErrSonicOSFormat
		}

		//FortiOS has their own syslog format and there is an example here, we try and detect their timestamp format if we run into an error
		//https://docs.fortinet.com/document/fortigate/7.4.2/fortios-log-message-reference/357866/log-message-fields
		if strings.Contains(string(p.buff), `eventtime=`) {
			return ts, syslogparser.ErrFortiOSFormat
		}

		if checkCiscoASA_RFC5424(p.buff) {
			return ts, syslogparser.ErrCiscoASARFC5424
		}

		return ts, fmt.Errorf("%v %s", syslogparser.ErrTimestampUnknownFormat, string(p.buff))
	}

	fixTimestampIfNeeded(&ts)

	p.cursor += tsFmtLen

	if (p.cursor < p.l) && (p.buff[p.cursor] == ' ') {
		p.cursor++
	}

	return ts, nil
}

func (p *Parser) parseHostname() (string, error) {
	oldcursor := p.cursor
	hostname, err := syslogparser.ParseHostname(p.buff, &p.cursor, p.l)
	if err == nil && len(hostname) > 0 && string(hostname[len(hostname)-1]) == ":" { // not a hostname! we found a GNU implementation of syslog()
		p.cursor = oldcursor - 1
		myhostname, err := os.Hostname()
		if err == nil {
			return myhostname, nil
		}
		return "", nil
	}
	return hostname, err
}

// http://tools.ietf.org/html/rfc3164#section-4.1.3
func (p *Parser) parseTag() (string, error) {
	var b byte
	var endOfTag bool
	var bracketOpen bool
	var tag []byte
	var err error
	var found bool

	from := p.cursor

	for {
		if p.cursor == p.l {
			// no tag found, reset cursor for content
			p.cursor = from
			return "", nil
		}

		b = p.buff[p.cursor]
		bracketOpen = (b == '[')
		endOfTag = (b == ':' || b == ' ')

		// XXX : parse PID ?
		if bracketOpen {
			tag = p.buff[from:p.cursor]
			found = true
		}

		if endOfTag {
			if !found {
				tag = p.buff[from:p.cursor]
				found = true
			}

			p.cursor++
			break
		}

		p.cursor++
	}

	if (p.cursor < p.l) && (p.buff[p.cursor] == ' ') {
		p.cursor++
	}

	return string(tag), err
}

func (p *Parser) movePastContent() error {
	if p.cursor > p.l {
		return syslogparser.ErrEOL
	}

	p.cursor += len(bytes.Trim(p.buff[p.cursor:p.l], " "))

	return syslogparser.ErrEOL
}

func fixTimestampIfNeeded(ts *time.Time) {
	now := time.Now().UTC()
	y := ts.Year()

	if ts.Year() == 0 {
		y = now.Year()
	}

	newTs := time.Date(y, ts.Month(), ts.Day(), ts.Hour(), ts.Minute(),
		ts.Second(), ts.Nanosecond(), ts.Location())

	*ts = newTs
}
