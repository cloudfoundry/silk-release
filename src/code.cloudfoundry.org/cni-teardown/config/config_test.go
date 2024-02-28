package config_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"code.cloudfoundry.org/cni-teardown/config"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Config", func() {
	var (
		datastorePath string
		dataDirPath   string
		tempDir       string
		configPath    string
	)

	BeforeEach(func() {
		datastorePath = "/data/store/path"
		dataDirPath = "/data/dir/path"

		var err error
		tempDir, err = ioutil.TempDir("", "")
		Expect(err).NotTo(HaveOccurred())
		configPath = filepath.Join(tempDir, "teardown-config.json")
		err = ioutil.WriteFile(configPath, []byte(fmt.Sprintf(`{
			"paths_to_delete": [
				%q,
				%q
			]
		}`, datastorePath, dataDirPath)), os.ModePerm)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should parse it", func() {
		result, err := config.LoadConfig(configPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(&config.Config{
			PathsToDelete: []string{
				datastorePath,
				dataDirPath,
			},
		}))
	})

	Context("when the path is invalid", func() {
		It("returns an error", func() {
			_, err := config.LoadConfig("/fake/path")
			Expect(err).To(MatchError("loading config: open /fake/path: no such file or directory"))
		})
	})

	Context("when the file contents are invalid json", func() {
		It("returns an error", func() {
			err := ioutil.WriteFile(configPath, []byte(`garbage`), os.ModePerm)
			Expect(err).NotTo(HaveOccurred())
			_, err = config.LoadConfig(configPath)
			Expect(err).To(MatchError(ContainSubstring("reading config: invalid character")))
		})
	})
})
