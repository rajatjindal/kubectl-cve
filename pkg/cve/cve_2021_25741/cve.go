package cve_2021_25741

import (
	"github.com/hashicorp/go-version"
	"github.com/rajatjindal/kubectl-cve/pkg/cve"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

type evaluator struct{}

func New() cve.Evaluator {
	return &evaluator{}
}

func (c *evaluator) Name() string {
	return "CVE-2021-25741"
}

func (c *evaluator) Metadata() map[string]string {
	return nil
}

func (c *evaluator) Effected(f cmdutil.Factory) (bool, error) {
	return c.evaluate(f)
}

func (c *evaluator) evaluate(f cmdutil.Factory) (bool, error) {
	discoveryClient, err := f.ToDiscoveryClient()
	if err != nil {
		return false, err
	}

	discoveryClient.Invalidate()
	serverVersion, err := discoveryClient.ServerVersion()
	if err != nil {
		return false, err
	}

	currentVersion, err := version.NewVersion(serverVersion.GitVersion)
	if err != nil {
		return false, err
	}

	// 	v1.22.0 - v1.22.1
	if currentVersion.GreaterThanOrEqual(fromstring("1.22.0")) && currentVersion.LessThanOrEqual(fromstring("1.22.1")) {
		return true, nil
	}

	// v1.21.0 - v1.21.4
	if currentVersion.GreaterThanOrEqual(fromstring("1.21.0")) && currentVersion.LessThanOrEqual(fromstring("1.21.4")) {
		return true, nil
	}

	// v1.20.0 - v1.20.10
	if currentVersion.GreaterThanOrEqual(fromstring("1.20.0")) && currentVersion.LessThanOrEqual(fromstring("1.20.10")) {
		return true, nil
	}

	// <= v1.19.14
	if currentVersion.LessThanOrEqual(fromstring("1.19.14")) {
		return true, nil
	}

	return false, nil
}

func fromstring(v string) *version.Version {
	vsn, _ := version.NewVersion(v)
	return vsn
}
