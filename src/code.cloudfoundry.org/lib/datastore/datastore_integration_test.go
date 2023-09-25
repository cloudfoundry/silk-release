package datastore_test

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"code.cloudfoundry.org/cf-networking-helpers/testsupport"
	"code.cloudfoundry.org/filelock"

	"code.cloudfoundry.org/lib/datastore"
	"code.cloudfoundry.org/lib/serial"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	UnprivilegedUserId  = uint32(65534)
	UnprivilegedGroupId = uint32(65534)
)

var _ = Describe("Datastore Lifecycle", func() {
	var (
		handle          string
		ip              string
		store           *datastore.Store
		metadata        map[string]interface{}
		dataFilePath    string
		lockFilePath    string
		versionFilePath string
	)

	BeforeEach(func() {
		handle = fmt.Sprintf("handle-%s-%d", randStringBytes(5), GinkgoParallelProcess())
		ip = fmt.Sprintf("192.168.0.%d", 100+GinkgoParallelProcess())
		metadata = map[string]interface{}{
			"AppID":         "some-appid",
			"OrgID":         "some-orgid",
			"PolicyGroupID": "some-policygroupid",
			"SpaceID":       "some-spaceid",
			"randomKey":     "randomValue",
		}

		tmpDir, err := os.MkdirTemp("", "")
		Expect(err).NotTo(HaveOccurred())

		lockFile, err := os.CreateTemp(tmpDir, "lock-file-")
		Expect(err).NotTo(HaveOccurred())
		lockFilePath = lockFile.Name()

		dataFile, err := os.CreateTemp(tmpDir, "data-file-")
		Expect(err).NotTo(HaveOccurred())
		dataFilePath = dataFile.Name()

		versionFile, err := os.CreateTemp(tmpDir, "version-file-")
		Expect(err).NotTo(HaveOccurred())
		versionFilePath = versionFile.Name()

		store = &datastore.Store{
			Serializer: &serial.Serial{},
			Locker: &filelock.Locker{
				FileLocker: filelock.NewLocker(lockFilePath),
				Mutex:      new(sync.Mutex),
			},
			DataFilePath:    dataFilePath,
			VersionFilePath: versionFilePath,
			LockedFilePath:  lockFilePath,
			CacheMutex:      new(sync.RWMutex),
			FileOwner:       "nobody",
			FileGroup:       "nogroup",
		}
	})

	AfterEach(func() {
		os.Remove(dataFilePath)
		os.Remove(versionFilePath)
		os.Remove(lockFilePath)
	})

	Context("when empty", func() {
		It("returns an empty map", func() {
			data, err := store.ReadAll()
			Expect(err).NotTo(HaveOccurred())
			Expect(len(data)).To(Equal(0))
		})
	})

	Context("when adding", func() {
		It("can add entry to datastore", func() {
			By("adding an entry to store")
			err := store.Add(handle, ip, metadata)
			Expect(err).NotTo(HaveOccurred())

			By("verify entry is in store")
			data, err := store.ReadAll()
			Expect(err).NotTo(HaveOccurred())
			Expect(data).Should(HaveKey(handle))

			Expect(data[handle].IP).To(Equal(ip))
			for k, v := range metadata {
				Expect(data[handle].Metadata).Should(HaveKeyWithValue(k, v))
			}
		})

		Context("when files are getting chowned", func() {
			It("chowns the store.* files to a non-root user", func() {
				By("adding an entry to store")
				err := store.Add(handle, ip, metadata)
				Expect(err).NotTo(HaveOccurred())

				By("verify store files are owned by user nobody")
				for _, filePath := range []string{lockFilePath, dataFilePath, versionFilePath} {
					fileInfo, err := os.Stat(filePath)
					Expect(err).NotTo(HaveOccurred())

					statInfo, ok := fileInfo.Sys().(*syscall.Stat_t)
					Expect(ok).To(BeTrue(), "unable to get the stat_t struct")

					Expect(statInfo.Uid).To(Equal(UnprivilegedUserId))
					Expect(statInfo.Gid).To(Equal(UnprivilegedGroupId))
				}
			})

			It("returns an error when file owner cannot be found", func() {
				store.FileOwner = "missingtestuser"
				err := store.Add(handle, ip, metadata)
				Expect(err).To(MatchError("user: unknown user missingtestuser"))
			})

			It("doesn't chown the owner/group it isn't set", func() {
				store.FileOwner = ""
				store.FileGroup = "nogroup"
				err := store.Add(handle, ip, metadata)
				Expect(err).NotTo(HaveOccurred())
				fileInfo, err := os.Stat(dataFilePath)
				statInfo, ok := fileInfo.Sys().(*syscall.Stat_t)
				Expect(ok).To(BeTrue(), "unable to get the stat_t struct")
				Expect(statInfo.Uid).NotTo(Equal(UnprivilegedUserId))
				Expect(statInfo.Gid).NotTo(Equal(UnprivilegedGroupId))

				store.FileOwner = "nobody"
				store.FileGroup = ""
				err = store.Add(handle, ip, metadata)
				Expect(err).NotTo(HaveOccurred())
				fileInfo, err = os.Stat(dataFilePath)
				statInfo, ok = fileInfo.Sys().(*syscall.Stat_t)
				Expect(ok).To(BeTrue(), "unable to get the stat_t struct")
				Expect(statInfo.Uid).NotTo(Equal(UnprivilegedUserId))
				Expect(statInfo.Gid).NotTo(Equal(UnprivilegedGroupId))
			})

			It("doesn't attempt a chown if file owner/group aren't set", func() {
				store.FileGroup = "missingtestgroup"
				err := store.Add(handle, ip, metadata)
				Expect(err).To(MatchError("group: unknown group missingtestgroup"))
			})
		})

		It("can add multiple entries to datastore", func() {
			total := 250
			By("adding an entries to store")
			for i := 0; i < total; i++ {
				id := fmt.Sprintf("%s-%d", handle, i)
				err := store.Add(id, ip, metadata)
				Expect(err).NotTo(HaveOccurred())
			}

			By("verify entries are in store")
			data, err := store.ReadAll()
			Expect(err).NotTo(HaveOccurred())
			Expect(data).Should(HaveLen(total))
		})
	})

	Context("when removing", func() {
		It("can add entry and remove an entry from datastore", func() {
			By("adding an entry to store")
			err := store.Add(handle, ip, metadata)
			Expect(err).NotTo(HaveOccurred())

			By("verify entry is in store")
			data, err := store.ReadAll()
			Expect(err).NotTo(HaveOccurred())
			Expect(data).Should(HaveLen(1))

			By("removing entry from store")
			deleted, err := store.Delete(handle)
			Expect(err).NotTo(HaveOccurred())
			Expect(deleted.Handle).To(Equal(handle))
			Expect(deleted.IP).To(Equal(ip))
			Expect(deleted.Metadata).To(Equal(metadata))

			By("verify entry no longer in store")
			data, err = store.ReadAll()
			Expect(err).NotTo(HaveOccurred())
			Expect(data).Should(BeEmpty())
		})

		Context("when files are getting chowned", func() {
			BeforeEach(func() {
				err := store.Add(handle, ip, metadata)
				Expect(err).NotTo(HaveOccurred())

				currentUser, err := user.Current()
				Expect(err).NotTo(HaveOccurred())

				uid, err := strconv.Atoi(currentUser.Uid)
				Expect(err).NotTo(HaveOccurred())

				gid, err := strconv.Atoi(currentUser.Gid)
				Expect(err).NotTo(HaveOccurred())

				err = os.Chown(versionFilePath, uid, gid)
				Expect(err).NotTo(HaveOccurred())

				err = os.Chown(lockFilePath, uid, gid)
				Expect(err).NotTo(HaveOccurred())

				err = os.Chown(dataFilePath, uid, gid)
				Expect(err).NotTo(HaveOccurred())
			})

			It("chowns the store.* files to a non-root user", func() {
				By("adding an entry to store")
				_, err := store.Delete(handle)
				Expect(err).NotTo(HaveOccurred())

				By("verify store files are owned by user nobody")
				for _, filePath := range []string{lockFilePath, dataFilePath, versionFilePath} {
					fileInfo, err := os.Stat(filePath)
					Expect(err).NotTo(HaveOccurred())

					statInfo, ok := fileInfo.Sys().(*syscall.Stat_t)
					Expect(ok).To(BeTrue(), "unable to get the stat_t struct")

					Expect(statInfo.Uid).To(Equal(UnprivilegedUserId))
					Expect(statInfo.Gid).To(Equal(UnprivilegedGroupId))
				}
			})

			It("returns an error when file owner cannot be found", func() {
				store.FileOwner = "missingtestuser"
				_, err := store.Delete(handle)
				Expect(err).To(MatchError("user: unknown user missingtestuser"))
			})

			It("returns an error when file group cannot be found", func() {
				store.FileGroup = "missingtestgroup"
				_, err := store.Delete(handle)
				Expect(err).To(MatchError("group: unknown group missingtestgroup"))
			})

			It("doesn't chown the owner/group it isn't set", func() {
				store.FileOwner = ""
				store.FileGroup = "nogroup"
				_, err := store.Delete(handle)
				Expect(err).NotTo(HaveOccurred())
				fileInfo, err := os.Stat(dataFilePath)
				statInfo, ok := fileInfo.Sys().(*syscall.Stat_t)
				Expect(ok).To(BeTrue(), "unable to get the stat_t struct")
				Expect(statInfo.Uid).NotTo(Equal(UnprivilegedUserId))
				Expect(statInfo.Gid).NotTo(Equal(UnprivilegedGroupId))

				store.FileOwner = "nobody"
				store.FileGroup = ""
				_, err = store.Delete(handle)
				Expect(err).NotTo(HaveOccurred())
				fileInfo, err = os.Stat(dataFilePath)
				statInfo, ok = fileInfo.Sys().(*syscall.Stat_t)
				Expect(ok).To(BeTrue(), "unable to get the stat_t struct")
				Expect(statInfo.Uid).NotTo(Equal(UnprivilegedUserId))
				Expect(statInfo.Gid).NotTo(Equal(UnprivilegedGroupId))
			})
		})

		It("can remove multiple entries to datastore", func() {
			total := 250
			By("adding an entries to store")
			for i := 0; i < total; i++ {
				id := fmt.Sprintf("%s-%d", handle, i)
				err := store.Add(id, ip, metadata)
				Expect(err).NotTo(HaveOccurred())
			}

			By("verify entries are in store")
			data, err := store.ReadAll()
			Expect(err).NotTo(HaveOccurred())
			Expect(data).Should(HaveLen(total))

			By("removing entries from store")
			for i := 0; i < total; i++ {
				id := fmt.Sprintf("%s-%d", handle, i)
				deleted, err := store.Delete(id)
				Expect(deleted.Handle).To(Equal(id))
				Expect(err).NotTo(HaveOccurred())
			}

			By("verify store is empty")
			data, err = store.ReadAll()
			Expect(err).NotTo(HaveOccurred())
			Expect(data).Should(BeEmpty())
		})
	})

	Context("when adding and deleting concurrently", func() {
		It("remains consistent", func() {

			containerHandles := []interface{}{}
			total := 250
			for i := 0; i < total; i++ {
				id := fmt.Sprintf("%s-%d", handle, i)
				containerHandles = append(containerHandles, id)
			}

			parallelRunner := &testsupport.ParallelRunner{
				NumWorkers: 50,
			}
			toDelete := make(chan (interface{}), total)
			toRead := make(chan (interface{}), total)

			go func() {
				parallelRunner.RunOnSlice(containerHandles, func(containerHandle interface{}) {
					p := containerHandle.(string)
					func(id string, toRead chan<- interface{}) {
						err := store.Add(id, ip, metadata)
						Expect(err).NotTo(HaveOccurred())
						toRead <- p
					}(p, toRead)
				})
				close(toRead)
			}()

			go func() {
				parallelRunner.RunOnChannel(toRead, func(containerHandle interface{}) {
					p := containerHandle.(string)
					func(id string, toDelete chan<- interface{}) {
						contents, err := store.ReadAll()
						Expect(err).NotTo(HaveOccurred())
						Expect(contents).To(HaveKey(p))
						toDelete <- p
					}(p, toDelete)
				})
				close(toDelete)
			}()

			var nDeleted int32
			parallelRunner.RunOnChannel(toDelete, func(containerHandle interface{}) {
				p := containerHandle.(string)
				func(id string) {
					_, err := store.Delete(id)
					Expect(err).NotTo(HaveOccurred())
				}(p)
				atomic.AddInt32(&nDeleted, 1)
			})
			Expect(nDeleted).To(Equal(int32(total)))

			By("adding an entries to store")
			data, err := store.ReadAll()
			Expect(err).NotTo(HaveOccurred())
			Expect(data).Should(HaveLen(0))

		})
	})
})
