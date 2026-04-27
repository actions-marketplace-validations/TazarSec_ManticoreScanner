package formatter

import (
	"encoding/json"

	"github.com/TazarSec/ManticoreScanner/pkg/api"
)

type JSONFormatter struct{}

func (f *JSONFormatter) Format(results []api.BatchResultItem, opts Options) ([]byte, error) {
	return json.MarshalIndent(results, "", "  ")
}
