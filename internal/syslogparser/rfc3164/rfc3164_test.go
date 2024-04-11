package rfc3164

import (
	"log"
	"testing"
	"time"

	"github.com/GLMONTER/go-syslog/internal/syslogparser"
	. "gopkg.in/check.v1"
)

// Hooks up gocheck into the gotest runner.
func Test(t *testing.T) { TestingT(t) }

type Rfc3164TestSuite struct {
}

var (
	_ = Suite(&Rfc3164TestSuite{})

	// XXX : corresponds to the length of the last tried timestamp format
	// XXX : Jan  2 15:04:05
	lastTriedTimestampLen = 15
)

func (s *Rfc3164TestSuite) TestParserCiscoASA_Valid_RFC5424(c *C) {
	buff := []byte(`<166>2018-06-27T12:17:46Z asa : %ASA-6-110002: Failed to locate egress interface for protocol from src interface :src IP/src port to dest IP/dest port`)

	p := NewParser(buff)
	expectedP := &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}

	c.Assert(p, DeepEquals, expectedP)

	err := p.Parse()
	c.Assert(err, IsNil)

	obtained := p.Dump()

	expected := syslogparser.LogParts{
		"timestamp": time.Date(2018, time.June, 27, 12, 17, 46, 0, time.UTC),
		"hostname":  "",
		"tag":       "",
		"content":   `<166>2018-06-27T12:17:46Z asa : %ASA-6-110002: Failed to locate egress interface for protocol from src interface :src IP/src port to dest IP/dest port`,
		"priority":  166,
		"facility":  20,
		"severity":  6,
	}

	c.Assert(obtained, DeepEquals, expected)
}

func (s *Rfc3164TestSuite) TestParserCiscoASA_NoTimestamp(c *C) {
	buff := []byte(`<34>:%ASA-session-6-106100: access-list outside_access_in permitted tcp outside/155.138.247.97(58344) -> NEX-DMZ/10.90.3.239(443) hit-cnt 1 first hit [0x8fca8d4d, 0xf3808cf3]`)

	p := NewParser(buff)
	expectedP := &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}

	c.Assert(p, DeepEquals, expectedP)

	err := p.Parse()
	c.Assert(err, IsNil)

	obtained := p.Dump()
	now := time.Now()
	log.Println(obtained)
	obtained["timestamp"] = now
	expected := syslogparser.LogParts{
		"timestamp": now,
		"hostname":  "",
		"tag":       "",
		"content":   `<34>:%ASA-session-6-106100: access-list outside_access_in permitted tcp outside/155.138.247.97(58344) -> NEX-DMZ/10.90.3.239(443) hit-cnt 1 first hit [0x8fca8d4d, 0xf3808cf3]`,
		"priority":  34,
		"facility":  4,
		"severity":  2,
	}

	c.Assert(obtained, DeepEquals, expected)
}

func (s *Rfc3164TestSuite) TestParserCiscoASA_Valid(c *C) {
	buff := []byte(`<34>:Apr 04 19:28:05 EDT: %ASA-session-6-106100: access-list outside_access_in permitted tcp outside/155.138.247.97(58344) -> NEX-DMZ/10.90.3.239(443) hit-cnt 1 first hit [0x8fca8d4d, 0xf3808cf3]`)

	p := NewParser(buff)
	expectedP := &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}

	c.Assert(p, DeepEquals, expectedP)

	err := p.Parse()
	c.Assert(err, IsNil)

	obtained := p.Dump()

	expected := syslogparser.LogParts{
		"timestamp": time.Date(2024, time.April, 04, 19, 28, 05, 0, time.UTC),
		"hostname":  "",
		"tag":       "",
		"content":   `<34>:Apr 04 19:28:05 EDT: %ASA-session-6-106100: access-list outside_access_in permitted tcp outside/155.138.247.97(58344) -> NEX-DMZ/10.90.3.239(443) hit-cnt 1 first hit [0x8fca8d4d, 0xf3808cf3]`,
		"priority":  34,
		"facility":  4,
		"severity":  2,
	}

	c.Assert(obtained, DeepEquals, expected)
}

func (s *Rfc3164TestSuite) TestParserSonicWall_Valid(c *C) {
	buff := []byte(`<34>id=firewall sn=18B1690729A8 fw=10.205.123.15 time="2016-08-19 18:05:44 UTC" pri=1 c=32 m=609 msg="IPS Prevention Alert: DNS named version attempt" sid=143 ipscat=DNS ipspri=3 n=3 src=192.168.169.180:2907 dst=172.16.2.11:53`)

	p := NewParser(buff)
	expectedP := &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}

	c.Assert(p, DeepEquals, expectedP)

	err := p.Parse()
	c.Assert(err, IsNil)

	obtained := p.Dump()
	expected := syslogparser.LogParts{
		"timestamp": time.Date(2016, time.August, 19, 18, 5, 44, 0, time.UTC),
		"hostname":  "10.205.123.15",
		"tag":       "",
		"content":   `<34>id=firewall sn=18B1690729A8 fw=10.205.123.15 time="2016-08-19 18:05:44 UTC" pri=1 c=32 m=609 msg="IPS Prevention Alert: DNS named version attempt" sid=143 ipscat=DNS ipspri=3 n=3 src=192.168.169.180:2907 dst=172.16.2.11:53`,
		"priority":  34,
		"facility":  4,
		"severity":  2,
	}

	c.Assert(obtained, DeepEquals, expected)
}

func (s *Rfc3164TestSuite) TestParserFortiOS_Valid(c *C) {
	buff := []byte(`<133>date=2024-01-31 time=13:36:54 devname="Y21FS1-101F" devid="FGUSI@#J%JI@I" eventtime=1706726214463347261 tz="-0500" logid="0000000011" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.2.2.30 srcport=50295 srcintf="almi-f5s" srcintfrole="undefined" dstip=10.3.1.1 dstport=90 dstintf="sr929" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=1583922 proto=3 action="start" policyid=905 policytype="policy" poluuid="fjkdsljjlk-5u39582305-573289527358" policyname="FIREWALL_POLICY" user="USER_ADMIN" authserver="AGENT_FO" dstuser="SVC_USER" centralnatid=5 service="TESTSERV" trandisp="noop" duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 rcvdpkt=0 vpntype="ipsecvpn" appcat="unscanned"`)

	p := NewParser(buff)
	expectedP := &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}

	c.Assert(p, DeepEquals, expectedP)

	err := p.Parse()
	c.Assert(err, IsNil)

	obtained := p.Dump()
	expected := syslogparser.LogParts{
		"timestamp": time.Date(2024, time.January, 31, 18, 36, 54, 463347261, time.UTC),
		"hostname":  "",
		"tag":       "",
		"content":   `<133>date=2024-01-31 time=13:36:54 devname="Y21FS1-101F" devid="FGUSI@#J%JI@I" eventtime=1706726214463347261 tz="-0500" logid="0000000011" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.2.2.30 srcport=50295 srcintf="almi-f5s" srcintfrole="undefined" dstip=10.3.1.1 dstport=90 dstintf="sr929" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=1583922 proto=3 action="start" policyid=905 policytype="policy" poluuid="fjkdsljjlk-5u39582305-573289527358" policyname="FIREWALL_POLICY" user="USER_ADMIN" authserver="AGENT_FO" dstuser="SVC_USER" centralnatid=5 service="TESTSERV" trandisp="noop" duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 rcvdpkt=0 vpntype="ipsecvpn" appcat="unscanned"`,
		"priority":  133,
		"facility":  16,
		"severity":  5,
	}

	c.Assert(obtained, DeepEquals, expected)
}

func (s *Rfc3164TestSuite) TestParser_Valid(c *C) {
	buff := []byte("<34>Oct 11 22:14:15 mymachine very.large.syslog.message.tag: 'su root' failed for lonvick on /dev/pts/8")

	p := NewParser(buff)
	expectedP := &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}

	c.Assert(p, DeepEquals, expectedP)

	err := p.Parse()
	c.Assert(err, IsNil)

	now := time.Now()

	obtained := p.Dump()
	expected := syslogparser.LogParts{
		"timestamp": time.Date(now.Year(), time.October, 11, 22, 14, 15, 0, time.UTC),
		"hostname":  "mymachine",
		"tag":       "very.large.syslog.message.tag",
		"content":   "<34>Oct 11 22:14:15 mymachine very.large.syslog.message.tag: 'su root' failed for lonvick on /dev/pts/8",
		"priority":  34,
		"facility":  4,
		"severity":  2,
	}

	c.Assert(obtained, DeepEquals, expected)
}

func (s *Rfc3164TestSuite) TestParser_ValidNoTag(c *C) {
	buff := []byte("<34>Oct 11 22:14:15 mymachine singleword")

	p := NewParser(buff)
	expectedP := &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}

	c.Assert(p, DeepEquals, expectedP)

	err := p.Parse()
	c.Assert(err, IsNil)

	now := time.Now()

	obtained := p.Dump()
	expected := syslogparser.LogParts{
		"timestamp": time.Date(now.Year(), time.October, 11, 22, 14, 15, 0, time.UTC),
		"hostname":  "mymachine",
		"tag":       "",
		"content":   "<34>Oct 11 22:14:15 mymachine singleword",
		"priority":  34,
		"facility":  4,
		"severity":  2,
	}

	c.Assert(obtained, DeepEquals, expected)
}

// RFC 3164 section 4.3.2
func (s *Rfc3164TestSuite) TestParser_NoTimestamp(c *C) {
	buff := []byte("<14>INFO     leaving (1) step postscripts")

	p := NewParser(buff)
	expectedP := &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}

	c.Assert(p, DeepEquals, expectedP)

	err := p.Parse()
	c.Assert(err, IsNil)

	now := time.Now()

	obtained := p.Dump()

	obtainedTime := obtained["timestamp"].(time.Time)
	s.assertTimeIsCloseToNow(c, obtainedTime)

	obtained["timestamp"] = now // XXX: Need to mock out time to test this fully
	expected := syslogparser.LogParts{
		"timestamp": now,
		"hostname":  "",
		"tag":       "",
		"content":   "<14>INFO     leaving (1) step postscripts",
		"priority":  14,
		"facility":  1,
		"severity":  6,
	}

	c.Assert(obtained, DeepEquals, expected)
}

// RFC 3164 section 4.3.3
func (s *Rfc3164TestSuite) TestParser_NoPriority(c *C) {
	buff := []byte("Oct 11 22:14:15 Testing no priority")

	p := NewParser(buff)
	expectedP := &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}

	c.Assert(p, DeepEquals, expectedP)

	err := p.Parse()
	c.Assert(err, IsNil)

	now := time.Now()

	obtained := p.Dump()
	obtainedTime := obtained["timestamp"].(time.Time)
	s.assertTimeIsCloseToNow(c, obtainedTime)

	obtained["timestamp"] = now // XXX: Need to mock out time to test this fully
	expected := syslogparser.LogParts{
		"timestamp": now,
		"hostname":  "",
		"tag":       "",
		"content":   "Oct 11 22:14:15 Testing no priority",
		"priority":  13,
		"facility":  1,
		"severity":  5,
	}

	c.Assert(obtained, DeepEquals, expected)
}

func (s *Rfc3164TestSuite) TestParseHeader_Valid(c *C) {
	buff := []byte("Oct 11 22:14:15 mymachine ")
	now := time.Now()
	hdr := header{
		timestamp: time.Date(now.Year(), time.October, 11, 22, 14, 15, 0, time.UTC),
		hostname:  "mymachine",
	}

	s.assertRfc3164Header(c, hdr, buff, 25, nil)

	// expected header for next two tests
	hdr = header{
		timestamp: time.Date(now.Year(), time.October, 1, 22, 14, 15, 0, time.UTC),
		hostname:  "mymachine",
	}
	// day with leading zero
	buff = []byte("Oct 01 22:14:15 mymachine ")
	s.assertRfc3164Header(c, hdr, buff, 25, nil)
	// day with leading space
	buff = []byte("Oct  1 22:14:15 mymachine ")
	s.assertRfc3164Header(c, hdr, buff, 25, nil)

}

func (s *Rfc3164TestSuite) TestParseHeader_RFC3339Timestamp(c *C) {
	buff := []byte("2018-01-12T22:14:15+00:00 mymachine app[101]: msg")
	hdr := header{
		timestamp: time.Date(2018, time.January, 12, 22, 14, 15, 0, time.UTC),
		hostname:  "mymachine",
	}
	s.assertRfc3164Header(c, hdr, buff, 35, nil)
}

func (s *Rfc3164TestSuite) TestParser_ValidRFC3339Timestamp(c *C) {
	buff := []byte("<34>2018-01-12T22:14:15+00:00 mymachine app[101]: msg")
	p := NewParser(buff)
	err := p.Parse()
	c.Assert(err, IsNil)
	obtained := p.Dump()
	expected := syslogparser.LogParts{
		"timestamp": time.Date(2018, time.January, 12, 22, 14, 15, 0, time.UTC),
		"hostname":  "mymachine",
		"tag":       "app",
		"content":   "<34>2018-01-12T22:14:15+00:00 mymachine app[101]: msg",
		"priority":  34,
		"facility":  4,
		"severity":  2,
	}
	c.Assert(obtained, DeepEquals, expected)
}

func (s *Rfc3164TestSuite) TestParseHeader_InvalidTimestamp(c *C) {
	buff := []byte("Oct 34 32:72:82 mymachine ")
	hdr := header{}

	s.assertRfc3164Header(c, hdr, buff, lastTriedTimestampLen+1, syslogparser.ErrTimestampUnknownFormat)
}

func (s *Rfc3164TestSuite) TestParsemessage_Valid(c *C) {
	content := "foo bar baz blah quux"
	buff := []byte("sometag[123]: " + content)
	hdr := rfc3164message{
		tag:     "sometag",
		content: string(buff),
	}

	s.assertRfc3164message(c, hdr, buff, len(buff), syslogparser.ErrEOL)
}

func (s *Rfc3164TestSuite) TestParseTimestamp_Invalid(c *C) {
	buff := []byte("Oct 34 32:72:82")
	ts := new(time.Time)

	s.assertTimestamp(c, *ts, buff, lastTriedTimestampLen, syslogparser.ErrTimestampUnknownFormat)
}

func (s *Rfc3164TestSuite) TestParseTimestamp_TrailingSpace(c *C) {
	// XXX : no year specified. Assumed current year
	// XXX : no timezone specified. Assume UTC
	buff := []byte("Oct 11 22:14:15 ")

	now := time.Now()
	ts := time.Date(now.Year(), time.October, 11, 22, 14, 15, 0, time.UTC)

	s.assertTimestamp(c, ts, buff, len(buff), nil)
}

func (s *Rfc3164TestSuite) TestParseTimestamp_OneDigitForMonths(c *C) {
	// XXX : no year specified. Assumed current year
	// XXX : no timezone specified. Assume UTC
	buff := []byte("Oct  1 22:14:15")

	now := time.Now()
	ts := time.Date(now.Year(), time.October, 1, 22, 14, 15, 0, time.UTC)

	s.assertTimestamp(c, ts, buff, len(buff), nil)
}

func (s *Rfc3164TestSuite) TestParseTimestamp_Valid(c *C) {
	// XXX : no year specified. Assumed current year
	// XXX : no timezone specified. Assume UTC
	buff := []byte("Oct 11 22:14:15")

	now := time.Now()
	ts := time.Date(now.Year(), time.October, 11, 22, 14, 15, 0, time.UTC)

	s.assertTimestamp(c, ts, buff, len(buff), nil)
}

func (s *Rfc3164TestSuite) TestParseTag_Pid(c *C) {
	buff := []byte("apache2[10]:")
	tag := "apache2"

	s.assertTag(c, tag, buff, len(buff), nil)
}

func (s *Rfc3164TestSuite) TestParseTag_NoPid(c *C) {
	buff := []byte("apache2:")
	tag := "apache2"

	s.assertTag(c, tag, buff, len(buff), nil)
}

func (s *Rfc3164TestSuite) TestParseTag_TrailingSpace(c *C) {
	buff := []byte("apache2: ")
	tag := "apache2"

	s.assertTag(c, tag, buff, len(buff), nil)
}

func (s *Rfc3164TestSuite) TestParseTag_NoTag(c *C) {
	buff := []byte("apache2")
	tag := ""

	s.assertTag(c, tag, buff, 0, nil)
}

func (s *Rfc3164TestSuite) BenchmarkParseTimestamp(c *C) {
	buff := []byte("Oct 11 22:14:15")

	p := NewParser(buff)

	for i := 0; i < c.N; i++ {
		_, err := p.parseTimestamp()
		if err != nil {
			panic(err)
		}

		p.cursor = 0
	}
}

func (s *Rfc3164TestSuite) BenchmarkParseHostname(c *C) {
	buff := []byte("gimli.local")

	p := NewParser(buff)

	for i := 0; i < c.N; i++ {
		_, err := p.parseHostname()
		if err != nil {
			panic(err)
		}

		p.cursor = 0
	}
}

func (s *Rfc3164TestSuite) BenchmarkParseTag(c *C) {
	buff := []byte("apache2[10]:")

	p := NewParser(buff)

	for i := 0; i < c.N; i++ {
		_, err := p.parseTag()
		if err != nil {
			panic(err)
		}

		p.cursor = 0
	}
}

func (s *Rfc3164TestSuite) BenchmarkParseHeader(c *C) {
	buff := []byte("Oct 11 22:14:15 mymachine ")

	p := NewParser(buff)

	for i := 0; i < c.N; i++ {
		_, err := p.parseHeader()
		if err != nil {
			panic(err)
		}

		p.cursor = 0
	}
}

func (s *Rfc3164TestSuite) BenchmarkParsemessage(c *C) {
	buff := []byte("sometag[123]: foo bar baz blah quux")

	p := NewParser(buff)

	for i := 0; i < c.N; i++ {
		_, err := p.parsemessage()
		if err != syslogparser.ErrEOL {
			panic(err)
		}

		p.cursor = 0
	}
}

func (s *Rfc3164TestSuite) assertTimestamp(c *C, ts time.Time, b []byte, expC int, e error) {
	p := NewParser(b)
	obtained, err := p.parseTimestamp()
	c.Assert(obtained, Equals, ts)
	c.Assert(p.cursor, Equals, expC)
	c.Assert(err, Equals, e)
}

func (s *Rfc3164TestSuite) assertTag(c *C, t string, b []byte, expC int, e error) {
	p := NewParser(b)
	obtained, err := p.parseTag()
	c.Assert(obtained, Equals, t)
	c.Assert(p.cursor, Equals, expC)
	c.Assert(err, Equals, e)
}

func (s *Rfc3164TestSuite) assertRfc3164Header(c *C, hdr header, b []byte, expC int, e error) {
	p := NewParser(b)
	obtained, err := p.parseHeader()
	c.Assert(err, Equals, e)
	c.Assert(obtained, Equals, hdr)
	c.Assert(p.cursor, Equals, expC)
}

func (s *Rfc3164TestSuite) assertRfc3164message(c *C, msg rfc3164message, b []byte, expC int, e error) {
	p := NewParser(b)
	obtained, err := p.parsemessage()
	c.Assert(err, Equals, e)
	c.Assert(obtained, Equals, msg)
	c.Assert(p.cursor, Equals, expC)
}

func (s *Rfc3164TestSuite) assertTimeIsCloseToNow(c *C, obtainedTime time.Time) {
	now := time.Now()
	timeStart := now.Add(-(time.Second * 5))
	timeEnd := now.Add(time.Second)
	c.Assert(obtainedTime.After(timeStart), Equals, true)
	c.Assert(obtainedTime.Before(timeEnd), Equals, true)
}
