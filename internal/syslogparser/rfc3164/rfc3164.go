package rfc3164

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
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
		location: time.UTC,
	}
}

func (p *Parser) Location(location *time.Location) {
	p.location = location
}

func (p *Parser) parseSonicWallHeader() (header, error) {
	//SonicOS log, do a regex parse because it is not standard
	//example log : <134>id=firewall sn=18B1690729A8 fw=10.205.123.15 time="2016-08-19 18:05:44" pri=1 c=32 m=609 msg="IPS Prevention Alert: DNS named version attempt" sid=143 ipscat=DNS ipspri=3 n=3 src=192.168.169.180:2907 dst=172.16.2.11:53
	pattern := `time="([^"]+)"`
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(string(p.buff))

	var timestamp string
	if match != nil && len(match) > 1 {
		timestamp = match[1]
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
		hostname:  "",
	}, nil
}

func (p *Parser) Parse() error {
	tcursor := p.cursor
	pri, err := p.parsePriority()
	if err != nil {
		p.message = rfc3164message{content: string(p.buff)}
		// RFC3164 sec 4.3.3
		p.priority = syslogparser.Priority{P: 13, F: syslogparser.Facility{Value: 1}, S: syslogparser.Severity{Value: 5}}
		p.cursor = tcursor
		p.header.timestamp = time.Now().Round(time.Second)
		err = p.movePastContent()
		if err != syslogparser.ErrEOL {
			return err
		}
		return nil
	}

	tcursor = p.cursor
	var skipMessageParse bool
	hdr, err := p.parseHeader()
	if err == syslogparser.ErrSonicOSFormat {
		skipMessageParse = true

		hdr, err = p.parseSonicWallHeader()
		if err != nil {
			return err
		}
	} else if strings.Contains(fmt.Sprintf("%s", err), syslogparser.ErrTimestampUnknownFormat.ErrorString) {
		// RFC3164 sec 4.3.2.
		hdr.timestamp = time.Now().Round(time.Second)
		// No tag processing should be done
		p.skipTag = true
		// Reset cursor for content read
		p.cursor = tcursor
	} else if err != nil {
		return err
	} else {
		p.cursor++
	}

	if !skipMessageParse {
		msg, err := p.parsemessage()
		if err != syslogparser.ErrEOL {
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

		//sonicOS has their own syslog format documented here, we try and detect their timestamp format if we run into an error
		//https://www.sonicwall.com/techdocs/pdf/sonicos-6-5-1-log-events-reference-guide.pdf
		if strings.Contains(string(p.buff), `time="`) {
			return ts, syslogparser.ErrSonicOSFormat
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
	now := time.Now()
	y := ts.Year()

	if ts.Year() == 0 {
		y = now.Year()
	}

	newTs := time.Date(y, ts.Month(), ts.Day(), ts.Hour(), ts.Minute(),
		ts.Second(), ts.Nanosecond(), ts.Location())

	*ts = newTs
}
