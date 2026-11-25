# go-edgetts

A self-contained Go client for the Microsoft Edge read-aloud protocol. It turns text into MP3 audio without any external TTS service — no API key, no server, no Python runtime.

## Install

```bash
go get github.com/afeiship/go-edgetts
```

## Quick start

```go
package main

import (
	"context"
	"log"
	"os"

	"github.com/afeiship/go-edgetts"
)

func main() {
	audio, err := edgetts.Synthesize(context.Background(), "What are you doing?", "en-US-AriaNeural")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("speech.mp3", audio, 0o644); err != nil {
		log.Fatal(err)
	}
}
```

Pass an empty voice string to use the default (`zh-CN-XiaoxiaoNeural`).

## API

| Function | Description |
| --- | --- |
| `Synthesize(ctx, text, voice) ([]byte, error)` | Synthesize text into MP3 bytes. Long text is split safely on rune boundaries. |
| `GenerateSecMSGEC(unixTime) (string, error)` | Generate the current Sec-MS-GEC v2 token (used internally). |

## Proxy

The WebSocket dialer reads proxy settings from the first non-empty environment variable:

```
EDGETTS_PROXY > EDGETTSD_PROXY > HTTPS_PROXY > https_proxy > HTTP_PROXY > http_proxy
```

If none is set, the connection is direct.

## Notes

- Microsoft's read-aloud endpoint is WebSocket-only; there is no plain HTTP synthesis API.
- Sec-MS-GEC **v2** is required — v1 tokens are rejected with HTTP 403. On a 403 the client automatically retries once with clock skew corrected from the server's `Date` header.
- The token digest is a modified SHA-256 (perturbed schedule and round constants), so `crypto/sha256` cannot be used. Fixed-vector tests in `drm_test.go` guard against regressions.
- If Microsoft changes the protocol or token version, update `secMSGECStrictVersion` and `userAgent` in the source.

## License

MIT. Ported from [rany2/edge-tts](https://github.com/rany2/edge-tts) (MIT).
