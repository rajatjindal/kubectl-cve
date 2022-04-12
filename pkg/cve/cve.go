package cve

import (
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

type Evaluator interface {
	Name() string
	Metadata() map[string]string
	Effected(f cmdutil.Factory) (bool, error)
}
