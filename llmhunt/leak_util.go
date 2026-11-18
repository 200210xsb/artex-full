package llmhunt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/Autumn-27/artex/db"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// pgKeyInsert 落一条 key（按指纹去重），返回是否新增。
func (s *Scanner) pgKeyInsert(srcURL, keyType, raw, sourceKind string) (bool, error) {
	sum := sha256.Sum256([]byte(raw))
	fp := hex.EncodeToString(sum[:8])
	ok, err := s.pg.InsertLLMKey(&db.LLMKey{
		URL:         srcURL,
		KeyType:     keyType,
		Raw:         raw,
		Masked:      mask(raw),
		Fingerprint: fp,
		Context:     keyType + " 出现在 " + srcURL,
		SourceKind:  sourceKind,
		Repo:        strings.TrimSpace(srcURL),
	})
	return ok, err
}
