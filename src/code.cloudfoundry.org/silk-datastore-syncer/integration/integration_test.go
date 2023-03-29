package integration_test

import (
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"sync"

	"code.cloudfoundry.org/filelock"
	"code.cloudfoundry.org/lib/datastore"
	"code.cloudfoundry.org/lib/serial"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	"github.com/onsi/gomega/ghttp"
)

var _ = Describe("Datastore syncer", func() {
	var (
		silkFile     *os.File
		silkLockFile *os.File
		fakeGarden   *ghttp.Server
		session      *gexec.Session
		store        *datastore.Store
	)

	BeforeEach(func() {
		var err error
		silkFile, err = os.CreateTemp(GinkgoT().TempDir(), "silkfile")
		Expect(err).ToNot(HaveOccurred())
		u, err := user.Current()
		Expect(err).ToNot(HaveOccurred())
		groups, err := u.GroupIds()
		Expect(err).ToNot(HaveOccurred())
		group, err := user.LookupGroupId(groups[0])
		Expect(err).ToNot(HaveOccurred())
		store = &datastore.Store{
			Serializer: &serial.Serial{},
			Locker: &filelock.Locker{
				FileLocker: filelock.NewLocker(silkFile.Name() + "_lock"),
				Mutex:      new(sync.Mutex),
			},
			DataFilePath:    silkFile.Name(),
			VersionFilePath: silkFile.Name() + "_version",
			LockedFilePath:  silkFile.Name() + "_lock",
			FileOwner:       u.Name,
			FileGroup:       group.Name,
			CacheMutex:      new(sync.RWMutex),
		}

		fakeGarden = ghttp.NewUnstartedServer()
		fakeGarden.AllowUnhandledRequests = false
		fakeGarden.RouteToHandler("GET", "/ping", ghttp.RespondWithJSONEncoded(http.StatusOK, struct{}{}))
		fakeGarden.Start()

		cmd := exec.Command(binaryPath, "-n", "1", "--gardenNetwork", "tcp", "--gardenAddr", fakeGarden.Addr(), "--silkFile", silkFile.Name(), "--silkFileOwner", u.Name, "--silkFileGroup", group.Name)
		session, err = gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		session.Kill().Wait()
		silkFile.Close()
		silkLockFile.Close()
		fakeGarden.Close()
	})

	It("updates the log config", func() {
		err := store.Add("test", "127.0.0.1", map[string]interface{}{"log_config": `{"guid":"test","index":0,"source_name":"test","tags":{"test":"value"}}`})
		Expect(err).ToNot(HaveOccurred())
		containers := struct {
			Handles []string
		}{
			Handles: []string{"test"},
		}
		properties := map[string]string{"log_config": `{"guid":"test","index":0,"source_name":"test","tags":{"test":"value2"}}`}
		fakeGarden.RouteToHandler("GET", "/containers", ghttp.RespondWithJSONEncoded(http.StatusOK, containers))
		fakeGarden.RouteToHandler("GET", "/containers/test/properties", ghttp.RespondWithJSONEncoded(http.StatusOK, properties))

		Eventually(func() datastore.Container {
			readContainers, err := store.ReadAll()
			Expect(err).ToNot(HaveOccurred())
			return readContainers["test"]
		}, 10).Should(Equal(datastore.Container{
			Handle:   "test",
			IP:       "127.0.0.1",
			Metadata: map[string]interface{}{"log_config": `{"guid":"test","index":0,"source_name":"test","tags":{"test":"value2"}}`},
		}))
	})
	It("doesn't add new entries, or remove old entries in the log config", func() {
		err := store.Add("test", "127.0.0.1", map[string]interface{}{"log_config": `{"guid":"test","index":0,"source_name":"test","tags":{"test":"value"}}`})
		Expect(err).ToNot(HaveOccurred())
		containers := struct {
			Handles []string
		}{
			Handles: []string{"test-non-exist"},
		}
		properties := map[string]string{"log_config": `{"guid":"test-non-exist","index":0,"source_name":"test-non-exist","tags":{"test":"value"}}`}
		fakeGarden.RouteToHandler("GET", "/containers", ghttp.RespondWithJSONEncoded(http.StatusOK, containers))
		fakeGarden.RouteToHandler("GET", "/containers/test-non-exist/properties", ghttp.RespondWithJSONEncoded(http.StatusOK, properties))

		Eventually(func() datastore.Container {
			readContainers, err := store.ReadAll()
			Expect(err).ToNot(HaveOccurred())
			return readContainers["test"]
		}, 10).Should(Equal(datastore.Container{
			Handle:   "test",
			IP:       "127.0.0.1",
			Metadata: map[string]interface{}{"log_config": `{"guid":"test","index":0,"source_name":"test","tags":{"test":"value"}}`},
		}))
	})

	It("doesn't crash when containers fails", func() {
		fakeGarden.RouteToHandler("GET", "/containers", ghttp.RespondWithJSONEncoded(http.StatusNotFound, struct{}{}))
		Consistently(session, 3).ShouldNot(gexec.Exit())
	})
	It("doesn't crash when container fails", func() {
		containers := struct {
			Handles []string
		}{
			Handles: []string{"test"},
		}
		fakeGarden.RouteToHandler("GET", "/containers", ghttp.RespondWithJSONEncoded(http.StatusOK, containers))
		fakeGarden.RouteToHandler("GET", "/containers/test/properties", ghttp.RespondWithJSONEncoded(http.StatusNotFound, struct{}{}))
		Consistently(session, 3).ShouldNot(gexec.Exit())
	})
})
