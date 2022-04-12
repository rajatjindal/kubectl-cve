package inventory

import (
	"strings"

	"github.com/rajatjindal/kubectl-cve/pkg/cve"
	cve_2021_25741 "github.com/rajatjindal/kubectl-cve/pkg/cve/cve_2021_25741"
)

var register = map[string]cve.Evaluator{}

func GetEvaluator(cve string) cve.Evaluator {
	return register[strings.ToLower(cve)]
}

func GetAllEvaluators() map[string]cve.Evaluator {
	return register
}

func Register(cve string, evaluator cve.Evaluator) {
	register[strings.ToLower(cve)] = evaluator
}

func init() {
	Register("CVE-2021-25741", cve_2021_25741.New())
}
