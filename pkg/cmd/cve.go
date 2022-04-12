package cmd

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/rajatjindal/kubectl-cve/pkg/inventory"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

//Version is set during build time
var Version = "unknown"
var defaultConfigFlags = genericclioptions.NewConfigFlags(true).WithDeprecatedPasswordFlag().WithDiscoveryBurst(300).WithDiscoveryQPS(50.0)

//CVEOptions is struct for cve command
type CVEOptions struct {
	configFlags *genericclioptions.ConfigFlags
	iostreams   genericclioptions.IOStreams

	args         []string
	kubeclient   kubernetes.Interface
	printVersion bool
	all          bool

	tokenRetriever *tokenRetriever
	f              cmdutil.Factory
}

// tokenRetriever helps to retrieve token
type tokenRetriever struct {
	rountTripper http.RoundTripper
	token        string
}

//RoundTrip gets token
func (t *tokenRetriever) RoundTrip(req *http.Request) (*http.Response, error) {
	header := req.Header.Get("authorization")
	switch {
	case strings.HasPrefix(header, "Bearer "):
		t.token = strings.ReplaceAll(header, "Bearer ", "")
	}

	return t.rountTripper.RoundTrip(req)
}

// NewCVEOptions provides an instance of CVEOptions with default values
func NewCVEOptions(streams genericclioptions.IOStreams) *CVEOptions {
	return &CVEOptions{
		configFlags: genericclioptions.NewConfigFlags(true),
		iostreams:   streams,
	}
}

// NewCmdCVE provides a cobra command wrapping CVEOptions
func NewCmdCVE(streams genericclioptions.IOStreams) *cobra.Command {
	o := NewCVEOptions(streams)

	cmd := &cobra.Command{
		Use:          "cve [flags]",
		Short:        "find out if your cluster is impacted by cve",
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			if o.printVersion {
				fmt.Println(Version)
				os.Exit(0)
			}

			if err := o.Complete(c, args); err != nil {
				return err
			}
			if err := o.Validate(); err != nil {
				return err
			}
			if err := o.Run(); err != nil {
				return err
			}

			return nil
		},
	}
	cmd.Flags().BoolVar(&o.all, "all", true, "Prints information about all supported cve")
	cmd.Flags().BoolVar(&o.printVersion, "version", false, "prints version of plugin")

	kubeConfigFlags := o.configFlags
	if kubeConfigFlags == nil {
		kubeConfigFlags = defaultConfigFlags
	}

	kubeConfigFlags.AddFlags(cmd.Flags())
	matchVersionKubeConfigFlags := cmdutil.NewMatchVersionFlags(kubeConfigFlags)
	matchVersionKubeConfigFlags.AddFlags(cmd.Flags())

	o.f = cmdutil.NewFactory(matchVersionKubeConfigFlags)

	return cmd
}

// Complete sets all information required for updating the current context
func (o *CVEOptions) Complete(cmd *cobra.Command, args []string) error {
	o.args = args

	config, err := o.configFlags.ToRESTConfig()
	if err != nil {
		return err
	}

	o.tokenRetriever = &tokenRetriever{}
	config.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		o.tokenRetriever.rountTripper = rt
		return o.tokenRetriever
	})

	o.kubeclient, err = kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	return nil
}

// Validate ensures that all required arguments and flag values are provided
func (o *CVEOptions) Validate() error {
	if len(o.args) > 0 {
		return fmt.Errorf("no arguments expected. got %d arguments", len(o.args))
	}

	return nil
}

// Run retrieves and print the subject that's currently authenticated
func (o *CVEOptions) Run() error {
	for k, e := range inventory.GetAllEvaluators() {
		effected, err := e.Effected(o.f)
		if err != nil {
			fmt.Printf("%s - %v\n", k, err)
			continue
		}

		fmt.Printf("%s - %t\n", k, effected)
	}

	return nil
}
