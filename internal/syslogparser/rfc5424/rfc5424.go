// Note to self : never try to code while looking after your kids
// The result might look like this : https://pbs.twimg.com/media/BXqSuYXIEAAscVA.png

package rfc5424

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"

	"github.com/GLMONTER/go-syslog/internal/syslogparser"
)

const (
	NILVALUE = '-'
)

var (
	ErrYearInvalid       = &syslogparser.ParserError{"Invalid year in timestamp"}
	ErrMonthInvalid      = &syslogparser.ParserError{"Invalid month in timestamp"}
	ErrDayInvalid        = &syslogparser.ParserError{"Invalid day in timestamp"}
	ErrHourInvalid       = &syslogparser.ParserError{"Invalid hour in timestamp"}
	ErrMinuteInvalid     = &syslogparser.ParserError{"Invalid minute in timestamp"}
	ErrSecondInvalid     = &syslogparser.ParserError{"Invalid second in timestamp"}
	ErrSecFracInvalid    = &syslogparser.ParserError{"Invalid fraction of second in timestamp"}
	ErrTimeZoneInvalid   = &syslogparser.ParserError{"Invalid time zone in timestamp"}
	ErrInvalidTimeFormat = &syslogparser.ParserError{"Invalid time format"}
	ErrInvalidAppName    = &syslogparser.ParserError{"Invalid app name"}
	ErrInvalidProcId     = &syslogparser.ParserError{"Invalid proc ID"}
	ErrInvalidMsgId      = &syslogparser.ParserError{"Invalid msg ID"}
	ErrNoStructuredData  = &syslogparser.ParserError{"No structured data"}
	ErrCiscoASARFC5424   = &syslogparser.ParserError{"Cisco ASA RFC5424"}
)

type Parser struct {
	buff            []byte
	cursor          int
	l               int
	header          header
	structuredData  string
	message         string
	isUnixTimestamp bool
}

type header struct {
	priority  syslogparser.Priority
	version   int
	timestamp time.Time
	hostname  string
	appName   string
	procId    string
	msgId     string
}

type partialTime struct {
	hour    int
	minute  int
	seconds int
	secFrac float64
}

type fullTime struct {
	pt  partialTime
	loc *time.Location
}

type fullDate struct {
	year  int
	month int
	day   int
}

func NewParser(buff []byte) *Parser {
	return &Parser{
		buff:   buff,
		cursor: 0,
		l:      len(buff),
	}
}

func (p *Parser) Location(location *time.Location) {
	// Ignore as RFC5424 syslog always has a timezone
}

func (p *Parser) Parse() error {
	p.message = string(p.buff)
	p.header.timestamp = time.Now().Round(time.Second)

	hdr, err := p.parseHeader()
	if err != nil {
		if errors.Is(err, ErrCiscoASARFC5424) {
			p.header = hdr
			p.structuredData = "-"
			p.header.version = 1
			return nil
		}
		return err
	}

	p.header = hdr

	//if the timestamp is a unix timestamp, we can infer it is a cisco Meraki device
	if p.isUnixTimestamp {
		//we don't want to try and attempt to parse structured data for Meraki logs
		p.structuredData = "-"
		return nil
	}
	sd, err := p.parseStructuredData()
	if err != nil {
		return err
	}

	p.structuredData = sd
	p.cursor++

	return nil
}

func (p *Parser) Dump() syslogparser.LogParts {
	return syslogparser.LogParts{
		"priority":        p.header.priority.P,
		"facility":        p.header.priority.F.Value,
		"severity":        p.header.priority.S.Value,
		"version":         p.header.version,
		"timestamp":       p.header.timestamp,
		"hostname":        p.header.hostname,
		"app_name":        p.header.appName,
		"proc_id":         p.header.procId,
		"msg_id":          p.header.msgId,
		"structured_data": p.structuredData,
		"message":         p.message,
	}
}

// HEADER = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID
func (p *Parser) parseHeader() (header, error) {
	hdr := header{}

	pri, err := p.parsePriority()
	if err != nil {
		return hdr, err
	}

	hdr.priority = pri

	ver, err := p.parseVersion()
	if err != nil {
		return hdr, err
	}
	hdr.version = ver
	p.cursor++

	ts, err := p.parseTimestamp()
	if err != nil {
		if errors.Is(err, ErrCiscoASARFC5424) {
			hdr.timestamp = ts
			return hdr, ErrCiscoASARFC5424
		}
		return hdr, err
	}

	hdr.timestamp = ts
	p.cursor++

	host, err := p.parseHostname()
	if err != nil {
		return hdr, err
	}

	hdr.hostname = host
	p.cursor++

	appName, err := p.parseAppName()
	if err != nil {
		return hdr, err
	}

	hdr.appName = appName
	p.cursor++

	procId, err := p.parseProcId()
	if err != nil {
		return hdr, nil
	}

	hdr.procId = procId
	p.cursor++

	msgId, err := p.parseMsgId()
	if err != nil {
		return hdr, nil
	}

	hdr.msgId = msgId
	p.cursor++

	return hdr, nil
}

func (p *Parser) parsePriority() (syslogparser.Priority, error) {
	return syslogparser.ParsePriority(p.buff, &p.cursor, p.l)
}

func (p *Parser) parseVersion() (int, error) {
	return syslogparser.ParseVersion(p.buff, &p.cursor, p.l)
}

// isUnixTimestamp checks if the buffer at the current cursor position starts with a Unix timestamp.
func isUnixTimestamp(buff []byte, cursor *int, l int) bool {
	startPos := *cursor
	digitCount := 0

	for i := startPos; i < l; i++ {
		if buff[i] == '.' {
			return digitCount >= 10 // Return true if at least 10 digits before the dot
		}

		if syslogparser.IsDigit(buff[i]) {
			digitCount++
			continue
		}

		break // Break on encountering a non-digit character
	}

	return digitCount >= 10 // Return true if at least 10 digits without a dot
}

// parseUnixTimestamp parses a Unix timestamp from the buffer
// and converts it to a time.Time object.
func parseUnixTimestamp(buff []byte, cursor *int, l int) (time.Time, error) {
	startPos := *cursor
	dotPos := -1
	for i := startPos; i < l; i++ {
		if buff[i] == '.' {
			dotPos = i
			break
		}
	}

	var intPartStr, fracPartStr string
	if dotPos == -1 {
		intPartStr = string(buff[startPos:])
		*cursor = l
	} else {
		intPartStr = string(buff[startPos:dotPos])
		// Find where the fractional part ends
		fracEnd := dotPos + 1
		for fracEnd < l && syslogparser.IsDigit(buff[fracEnd]) {
			fracEnd++
		}
		fracPartStr = string(buff[dotPos+1 : fracEnd])
		*cursor = fracEnd
	}

	sec, err := strconv.ParseInt(intPartStr, 10, 64)
	if err != nil {
		return time.Time{}, err
	}

	var nsec int64 = 0
	if fracPartStr != "" {
		// Convert fractional part to a float then to nanoseconds
		fracSec, err := strconv.ParseFloat("0."+fracPartStr, 64)
		if err != nil {
			return time.Time{}, err
		}
		nsec = int64(fracSec * 1e9)
	}

	return time.Unix(sec, nsec), nil
}

const ciscoASATimestampCapture = `^<\d+>(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)`

var ciscoASATimestampRegexp = regexp.MustCompile(ciscoASATimestampCapture)

// https://tools.ietf.org/html/rfc5424#section-6.2.3
func (p *Parser) parseTimestamp() (time.Time, error) {
	ts := time.Now()

	if p.cursor >= p.l {
		return ts, fmt.Errorf("%v %s", ErrInvalidTimeFormat, string(p.buff))
	}

	if p.buff[p.cursor] == NILVALUE {
		p.cursor++
		return ts, nil
	}

	// Check if the timestamp is in Unix format (e.g., 1701233380.285170542)
	if isUnixTimestamp(p.buff, &p.cursor, p.l) {
		p.isUnixTimestamp = true
		unixTs, err := parseUnixTimestamp(p.buff, &p.cursor, p.l)
		if err != nil {
			return ts, err
		}
		return unixTs, nil
	}

	fd, err := parseFullDate(p.buff, &p.cursor, p.l)
	if err != nil {
		if errors.Is(err, ErrCiscoASARFC5424) {
			match := ciscoASATimestampRegexp.FindStringSubmatch(string(p.buff))
			if match != nil && len(match) > 1 {
				timestampStr := match[1]
				parsedTime, err := time.Parse(time.RFC3339, timestampStr)
				if err != nil {
					return ts, fmt.Errorf("failed to parse cisco ASA RFC5424 timestamp: %v", err)
				}
				return parsedTime, ErrCiscoASARFC5424
			}
		} else {
			return ts, err
		}
	}

	if p.cursor >= p.l || p.buff[p.cursor] != 'T' {
		return ts, fmt.Errorf("%v %s", ErrInvalidTimeFormat, string(p.buff))
	}

	p.cursor++

	ft, err := parseFullTime(p.buff, &p.cursor, p.l)
	if err != nil {
		return ts, fmt.Errorf("%v %s", syslogparser.ErrTimestampUnknownFormat, string(p.buff))
	}

	nSec, err := toNSec(ft.pt.secFrac)
	if err != nil {
		return ts, err
	}

	ts = time.Date(
		fd.year,
		time.Month(fd.month),
		fd.day,
		ft.pt.hour,
		ft.pt.minute,
		ft.pt.seconds,
		nSec,
		ft.loc,
	)

	return ts, nil
}

// HOSTNAME = NILVALUE / 1*255PRINTUSASCII
func (p *Parser) parseHostname() (string, error) {
	return syslogparser.ParseHostname(p.buff, &p.cursor, p.l)
}

// APP-NAME = NILVALUE / 1*48PRINTUSASCII
func (p *Parser) parseAppName() (string, error) {
	return parseUpToLen(p.buff, &p.cursor, p.l, 48, ErrInvalidAppName)
}

// PROCID = NILVALUE / 1*128PRINTUSASCII
func (p *Parser) parseProcId() (string, error) {
	return parseUpToLen(p.buff, &p.cursor, p.l, 128, ErrInvalidProcId)
}

// MSGID = NILVALUE / 1*32PRINTUSASCII
func (p *Parser) parseMsgId() (string, error) {
	return parseUpToLen(p.buff, &p.cursor, p.l, 32, ErrInvalidMsgId)
}

func (p *Parser) parseStructuredData() (string, error) {
	return parseStructuredData(p.buff, &p.cursor, p.l)
}

// ----------------------------------------------
// https://tools.ietf.org/html/rfc5424#section-6
// ----------------------------------------------

// XXX : bind them to Parser ?

// FULL-DATE : DATE-FULLYEAR "-" DATE-MONTH "-" DATE-MDAY
func parseFullDate(buff []byte, cursor *int, l int) (fullDate, error) {
	var fd fullDate

	year, err := parseYear(buff, cursor, l)
	if err != nil {
		return fd, err
	}

	if *cursor >= l || buff[*cursor] != '-' {
		return fd, fmt.Errorf("%v %s", syslogparser.ErrTimestampUnknownFormat, string(buff))
	}

	*cursor++

	month, err := parseMonth(buff, cursor, l)
	if err != nil {
		return fd, err
	}

	if *cursor >= l || buff[*cursor] != '-' {
		return fd, fmt.Errorf("%v %s", syslogparser.ErrTimestampUnknownFormat, string(buff))
	}

	*cursor++

	day, err := parseDay(buff, cursor, l)
	if err != nil {
		return fd, err
	}

	fd = fullDate{
		year:  year,
		month: month,
		day:   day,
	}

	return fd, nil
}

const ciscoASA_RFC5424Format = `^<\d+>(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)`

var ciscoASA_RFC5424Regexp = regexp.MustCompile(ciscoASA_RFC5424Format)

func checkCiscoASA_RFC5424(buff []byte) bool {
	if ciscoASA_RFC5424Regexp.MatchString(string(buff)) {
		return true
	}

	return false
}

// DATE-FULLYEAR   = 4DIGIT
func parseYear(buff []byte, cursor *int, l int) (int, error) {
	yearLen := 4

	if *cursor+yearLen > l {
		return 0, syslogparser.ErrEOL
	}

	// XXX : we do not check for a valid year (ie. 1999, 2013 etc)
	// XXX : we only checks the format is correct
	sub := string(buff[*cursor : *cursor+yearLen])

	*cursor += yearLen

	year, err := strconv.Atoi(sub)
	if err != nil {
		if checkCiscoASA_RFC5424(buff) {
			return 0, ErrCiscoASARFC5424
		}
		return 0, ErrYearInvalid
	}

	return year, nil
}

// DATE-MONTH = 2DIGIT  ; 01-12
func parseMonth(buff []byte, cursor *int, l int) (int, error) {
	return syslogparser.Parse2Digits(buff, cursor, l, 1, 12, ErrMonthInvalid)
}

// DATE-MDAY = 2DIGIT  ; 01-28, 01-29, 01-30, 01-31 based on month/year
func parseDay(buff []byte, cursor *int, l int) (int, error) {
	// XXX : this is a relaxed constraint
	// XXX : we do not check if valid regarding February or leap years
	// XXX : we only checks that day is in range [01 -> 31]
	// XXX : in other words this function will not rant if you provide Feb 31th
	return syslogparser.Parse2Digits(buff, cursor, l, 1, 31, ErrDayInvalid)
}

// FULL-TIME = PARTIAL-TIME TIME-OFFSET
func parseFullTime(buff []byte, cursor *int, l int) (fullTime, error) {
	var loc = new(time.Location)
	var ft fullTime

	pt, err := parsePartialTime(buff, cursor, l)
	if err != nil {
		return ft, err
	}

	loc, err = parseTimeOffset(buff, cursor, l)
	if err != nil {
		return ft, err
	}

	ft = fullTime{
		pt:  pt,
		loc: loc,
	}

	return ft, nil
}

// PARTIAL-TIME = TIME-HOUR ":" TIME-MINUTE ":" TIME-SECOND[TIME-SECFRAC]
func parsePartialTime(buff []byte, cursor *int, l int) (partialTime, error) {
	var pt partialTime

	hour, minute, err := getHourMinute(buff, cursor, l)
	if err != nil {
		return pt, err
	}

	if *cursor >= l || buff[*cursor] != ':' {
		return pt, fmt.Errorf("%v %s", ErrInvalidTimeFormat, string(buff))
	}

	*cursor++

	// ----

	seconds, err := parseSecond(buff, cursor, l)
	if err != nil {
		return pt, err
	}

	pt = partialTime{
		hour:    hour,
		minute:  minute,
		seconds: seconds,
	}

	// ----

	if *cursor >= l || buff[*cursor] != '.' {
		return pt, nil
	}

	*cursor++

	secFrac, err := parseSecFrac(buff, cursor, l)
	if err != nil {
		return pt, nil
	}
	pt.secFrac = secFrac

	return pt, nil
}

// TIME-HOUR = 2DIGIT  ; 00-23
func parseHour(buff []byte, cursor *int, l int) (int, error) {
	return syslogparser.Parse2Digits(buff, cursor, l, 0, 23, ErrHourInvalid)
}

// TIME-MINUTE = 2DIGIT  ; 00-59
func parseMinute(buff []byte, cursor *int, l int) (int, error) {
	return syslogparser.Parse2Digits(buff, cursor, l, 0, 59, ErrMinuteInvalid)
}

// TIME-SECOND = 2DIGIT  ; 00-59
func parseSecond(buff []byte, cursor *int, l int) (int, error) {
	return syslogparser.Parse2Digits(buff, cursor, l, 0, 59, ErrSecondInvalid)
}

// TIME-SECFRAC = "." 1*6DIGIT
func parseSecFrac(buff []byte, cursor *int, l int) (float64, error) {
	maxDigitLen := 6

	max := *cursor + maxDigitLen
	from := *cursor
	to := from

	for to = from; to < max; to++ {
		if to >= l {
			break
		}

		c := buff[to]
		if !syslogparser.IsDigit(c) {
			break
		}
	}

	sub := string(buff[from:to])
	if len(sub) == 0 {
		return 0, ErrSecFracInvalid
	}

	secFrac, err := strconv.ParseFloat("0."+sub, 64)
	*cursor = to
	if err != nil {
		return 0, ErrSecFracInvalid
	}

	return secFrac, nil
}

// TIME-OFFSET = "Z" / TIME-NUMOFFSET
func parseTimeOffset(buff []byte, cursor *int, l int) (*time.Location, error) {

	if *cursor >= l || buff[*cursor] == 'Z' {
		*cursor++
		return time.UTC, nil
	}

	return parseNumericalTimeOffset(buff, cursor, l)
}

// TIME-NUMOFFSET  = ("+" / "-") TIME-HOUR ":" TIME-MINUTE
func parseNumericalTimeOffset(buff []byte, cursor *int, l int) (*time.Location, error) {
	var loc = new(time.Location)

	sign := buff[*cursor]

	if (sign != '+') && (sign != '-') {
		return loc, ErrTimeZoneInvalid
	}

	*cursor++

	hour, minute, err := getHourMinute(buff, cursor, l)
	if err != nil {
		return loc, err
	}

	tzStr := fmt.Sprintf("%s%02d:%02d", string(sign), hour, minute)
	tmpTs, err := time.Parse("-07:00", tzStr)
	if err != nil {
		return loc, err
	}

	return tmpTs.Location(), nil
}

func getHourMinute(buff []byte, cursor *int, l int) (int, int, error) {
	hour, err := parseHour(buff, cursor, l)
	if err != nil {
		return 0, 0, err
	}

	if *cursor >= l || buff[*cursor] != ':' {
		return 0, 0, fmt.Errorf("%v %s", ErrInvalidTimeFormat, string(buff))
	}

	*cursor++

	minute, err := parseMinute(buff, cursor, l)
	if err != nil {
		return 0, 0, err
	}

	return hour, minute, nil
}

func toNSec(sec float64) (int, error) {
	_, frac := math.Modf(sec)
	fracStr := strconv.FormatFloat(frac, 'f', 9, 64)
	fracInt, err := strconv.Atoi(fracStr[2:])
	if err != nil {
		return 0, err
	}

	return fracInt, nil
}

// ------------------------------------------------
// https://tools.ietf.org/html/rfc5424#section-6.3
// ------------------------------------------------

func parseStructuredData(buff []byte, cursor *int, l int) (string, error) {
	var sdData string
	var found bool

	if *cursor >= l {
		return "-", nil
	}

	if buff[*cursor] == NILVALUE {
		*cursor++
		return "-", nil
	}

	if buff[*cursor] != '[' {
		return sdData, fmt.Errorf("%v %s", ErrNoStructuredData, string(buff))
	}

	from := *cursor
	to := from

	for to = from; to < l; to++ {
		if found {
			break
		}

		b := buff[to]

		if b == ']' {
			switch t := to + 1; {
			case t == l:
				found = true
			case t <= l && buff[t] == ' ':
				found = true
			}
		}
	}

	if found {
		*cursor = to
		return string(buff[from:to]), nil
	}

	return sdData, fmt.Errorf("%v %s", ErrNoStructuredData, string(buff))
}

func parseUpToLen(buff []byte, cursor *int, l int, maxLen int, e error) (string, error) {
	var to int
	var found bool
	var result string

	max := *cursor + maxLen

	for to = *cursor; (to <= max) && (to < l); to++ {
		if buff[to] == ' ' {
			found = true
			break
		}
	}

	if found {
		result = string(buff[*cursor:to])
	} else if to > max {
		to = max // don't go past max
	}

	*cursor = to

	if found {
		return result, nil
	}

	return "", e
}
