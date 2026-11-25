package edgetts

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	baseURL        = "speech.platform.bing.com/consumer/speech/synthesize/readaloud"
	wssURL         = "wss://" + baseURL + "/edge/v1"
	origin         = "chrome-extension://jdiccldimpdaibmpdkjnbmckianbfold"
	userAgent      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"
	dateLayout     = "Mon Jan 02 2006 15:04:05 GMT+0000 (Coordinated Universal Time)"
	defaultVoice   = "zh-CN-XiaoxiaoNeural"
	maxTextRunes   = 2000
	synthesizeWait = 60 * time.Second
)

var clockSkew int64

func nowUnix() int64 { return time.Now().Unix() + atomic.LoadInt64(&clockSkew) }

func adjustClockSkew(header http.Header) {
	serverDate := header.Get("Date")
	if serverDate == "" {
		return
	}
	serverTime, err := http.ParseTime(serverDate)
	if err != nil {
		return
	}
	atomic.StoreInt64(&clockSkew, serverTime.Unix()-time.Now().Unix())
}

// Synthesize turns text into MP3 audio using the Edge read-aloud endpoint.
// A 403 triggers one retry with clock skew corrected from the server's Date.
func Synthesize(ctx context.Context, text, voice string) ([]byte, error) {
	if strings.TrimSpace(text) == "" {
		return nil, fmt.Errorf("text is empty")
	}
	if voice == "" {
		voice = defaultVoice
	}
	var audio []byte
	for _, chunk := range splitText(text, maxTextRunes) {
		part, err := synthesizeChunk(ctx, chunk, voice)
		if err != nil {
			return nil, err
		}
		audio = append(audio, part...)
	}
	if len(audio) == 0 {
		return nil, fmt.Errorf("no audio returned")
	}
	return audio, nil
}

func synthesizeChunk(ctx context.Context, text, voice string) ([]byte, error) {
	for attempt := 0; attempt < 2; attempt++ {
		audio, resp, err := streamChunk(ctx, text, voice)
		if err == nil {
			return audio, nil
		}
		if attempt == 0 && resp != nil && resp.StatusCode == http.StatusForbidden {
			adjustClockSkew(resp.Header)
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("synthesis unauthorized after clock skew retry")
}

func streamChunk(ctx context.Context, text, voice string) ([]byte, *http.Response, error) {
	token, err := GenerateSecMSGEC(nowUnix())
	if err != nil {
		return nil, nil, err
	}
	muid := make([]byte, 16)
	if _, err := rand.Read(muid); err != nil {
		return nil, nil, err
	}
	headers := http.Header{}
	headers.Set("User-Agent", userAgent)
	headers.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	headers.Set("Accept-Language", "en-US,en;q=0.9")
	headers.Set("Cookie", "muid="+strings.ToUpper(hex.EncodeToString(muid))+";")
	headers.Set("Origin", origin)
	headers.Set("Pragma", "no-cache")
	headers.Set("Cache-Control", "no-cache")
	// gorilla/websocket sets Sec-WebSocket-Version and Upgrade itself.

	u := wssURL + "?TrustedClientToken=" + trustedClientToken +
		"&ConnectionId=" + randomHex() +
		"&Sec-MS-GEC=" + url.QueryEscape(token) +
		"&Sec-MS-GEC-Version=" + secMSGECStrictVersion

	dialer := websocket.Dialer{
		Proxy:             proxyResolver(),
		HandshakeTimeout:  15 * time.Second,
		EnableCompression: true,
		ReadBufferSize:    4096,
		WriteBufferSize:   4096,
	}
	conn, resp, err := dialer.DialContext(ctx, u, headers)
	if err != nil {
		if resp == nil {
			return nil, nil, fmt.Errorf("connect Edge TTS: %w", err)
		}
		return nil, resp, fmt.Errorf("connect Edge TTS: HTTP %d: %w", resp.StatusCode, err)
	}
	defer conn.Close()
	conn.SetReadLimit(32 << 20)
	_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	_ = conn.SetReadDeadline(time.Now().Add(synthesizeWait))

	stamp := time.Now().UTC().Format(dateLayout)
	config := "X-Timestamp:" + stamp + "\r\nContent-Type:application/json; charset=utf-8\r\nPath:speech.config\r\n\r\n" +
		`{"context":{"synthesis":{"audio":{"metadataoptions":{"sentenceBoundaryEnabled":"true","wordBoundaryEnabled":"false"},"outputFormat":"audio-24khz-48kbitrate-mono-mp3"}}}}` + "\r\n"
	if err := conn.WriteMessage(websocket.TextMessage, []byte(config)); err != nil {
		return nil, nil, fmt.Errorf("send speech config: %w", err)
	}

	ssml := fmt.Sprintf(
		"<speak version='1.0' xmlns='http://www.w3.org/2001/10/synthesis' xml:lang='en-US'>"+
			"<voice name='%s'><prosody pitch='+0Hz' rate='+0%%' volume='+0%%'>%s</prosody></voice></speak>",
		voice, text)
	request := fmt.Sprintf("X-RequestId:%s\r\nContent-Type:application/ssml+xml\r\nX-Timestamp:%sZ\r\nPath:ssml\r\n\r\n%s", randomHex(), stamp, ssml)
	if err := conn.WriteMessage(websocket.TextMessage, []byte(request)); err != nil {
		return nil, nil, fmt.Errorf("send ssml: %w", err)
	}

	var audio []byte
	for {
		messageType, payload, err := conn.ReadMessage()
		if err != nil {
			return nil, nil, fmt.Errorf("read Edge TTS stream: %w", err)
		}
		switch messageType {
		case websocket.BinaryMessage:
			fields, data, err := parseBinaryFrame(payload)
			if err != nil {
				return nil, nil, err
			}
			if fields["Path"] == "audio" {
				audio = append(audio, data...)
			}
		case websocket.TextMessage:
			at := strings.Index(string(payload), "\r\n\r\n")
			if at < 0 {
				continue
			}
			fields, err := parseHeaders(payload[:at])
			if err != nil {
				return nil, nil, err
			}
			if fields["Path"] == "turn.end" {
				return audio, nil, nil
			}
		}
	}
}

func proxyResolver() func(*http.Request) (*url.URL, error) {
	raw := ""
	for _, key := range []string{"EDGETTS_PROXY", "EDGETTSD_PROXY", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			raw = v
			break
		}
	}
	if raw == "" {
		return func(*http.Request) (*url.URL, error) { return nil, nil }
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return func(*http.Request) (*url.URL, error) { return nil, nil }
	}
	return func(*http.Request) (*url.URL, error) { return parsed, nil }
}

func randomHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func parseBinaryFrame(payload []byte) (map[string]string, []byte, error) {
	if len(payload) < 2 {
		return nil, nil, fmt.Errorf("binary frame is missing header length")
	}
	headerLen := int(binary.BigEndian.Uint16(payload[:2]))
	if headerLen < 2 || 2+headerLen > len(payload) {
		return nil, nil, fmt.Errorf("binary frame header length exceeds payload")
	}
	fields, err := parseHeaders(payload[2 : 2+headerLen])
	return fields, payload[2+headerLen:], err
}

func parseHeaders(raw []byte) (map[string]string, error) {
	fields := make(map[string]string)
	for _, line := range strings.Split(string(raw), "\r\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("malformed frame header %q", line)
		}
		fields[key] = strings.TrimSpace(value)
	}
	return fields, nil
}

// splitText escapes XML and splits on rune boundaries, so entities and
// multi-byte characters are never cut in half.
func splitText(text string, limit int) []string {
	runes := []rune(strings.TrimSpace(text))
	var chunks []string
	var current strings.Builder
	size := 0
	for _, r := range runes {
		if r <= 8 || (r >= 11 && r <= 12) || (r >= 14 && r <= 31) {
			r = ' '
		}
		var escaped strings.Builder
		_ = xml.EscapeText(&escaped, []byte(string(r)))
		if size+escaped.Len() > limit && current.Len() > 0 {
			chunks = append(chunks, current.String())
			current.Reset()
			size = 0
		}
		current.WriteString(escaped.String())
		size += escaped.Len()
	}
	if current.Len() > 0 {
		chunks = append(chunks, current.String())
	}
	return chunks
}
