package config_test

import (
	"os"

	"code.cloudfoundry.org/silk-daemon-bootstrap/config"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Config", func() {
	Describe("New", func() {
		var (
			file *os.File
			err  error
		)

		BeforeEach(func() {
			file, err = os.CreateTemp(os.TempDir(), "config-")
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when config file is valid", func() {
			It("returns the config", func() {
				file.WriteString(`{
					"policy_server_url": "https://some-url:1234",
					"policy_server_ca_cert_file": "/some/ca/file",
					"policy_client_cert_file": "/some/client/cert/file",
					"policy_client_key_file": "/some/client/key/file",
					"iptables_lock_file":  "/var/vcap/data/lock",
					"single_ip_only": true
				}`)
				c, err := config.New(file.Name())
				Expect(err).NotTo(HaveOccurred())
				Expect(c.PolicyServerURL).To(Equal("https://some-url:1234"))
				Expect(c.PolicyServerCACertFile).To(Equal("/some/ca/file"))
				Expect(c.PolicyClientCertFile).To(Equal("/some/client/cert/file"))
				Expect(c.PolicyClientKeyFile).To(Equal("/some/client/key/file"))
				Expect(c.IPTablesLockFile).To(Equal("/var/vcap/data/lock"))
				Expect(c.SingleIPOnly).To(Equal(true))
			})
		})

		Context("when config file path does not exist", func() {
			It("returns the error", func() {
				_, err := config.New("not-exists")
				Expect(err).To(MatchError(ContainSubstring("file does not exist:")))
			})
		})

		Context("when config file is bad format", func() {
			It("returns the error", func() {
				file.WriteString("bad-format")
				_, err = config.New(file.Name())
				Expect(err).To(MatchError(ContainSubstring("parsing config")))
			})
		})

		Context("when config file contents blank", func() {
			It("returns the error", func() {
				_, err = config.New(file.Name())
				Expect(err).To(MatchError(ContainSubstring("parsing config")))
			})
		})
	})
})
