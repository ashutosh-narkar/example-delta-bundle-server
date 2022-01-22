package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/ast"

	"github.com/open-policy-agent/opa/bundle"

	"github.com/go-ldap/ldap/v3"
)

type ldapClient struct {
	host         string
	port         int
	base         string
	bindDN       string
	bindPassword string
	conn         *ldap.Conn
	mtx          sync.Mutex
	members      []string
	revision     int
	subscribers  []chan update
}

type server struct {
	lc        *ldapClient
	deltaMode bool
}

type update struct {
	data     string
	revision int
}

// Connect connects to LDAP server
func (lc *ldapClient) Connect() error {
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", lc.host, lc.port))
	if err != nil {
		return err
	}

	lc.conn = l
	return nil
}

// Bind binds to LDAP server
func (lc *ldapClient) Bind() error {
	err := lc.Connect()
	if err != nil {
		return err
	}

	err = lc.conn.Bind(lc.bindDN, lc.bindPassword)
	if err != nil {
		return err
	}
	return nil
}

// Close closes the ldap connection
func (lc *ldapClient) Close() {
	if lc.conn != nil {
		lc.conn.Close()
		lc.conn = nil
	}
}

// AddOU adds an organizational unit (OU) entry to the LDAP tree
func (lc *ldapClient) AddOU(ou string) error {
	addReq := ldap.NewAddRequest(fmt.Sprintf("OU=%s,%s", ou, lc.base), []ldap.Control{})
	addReq.Attribute("objectClass", []string{"organizationalUnit"})
	addReq.Attribute("ou", []string{ou})

	if err := lc.conn.Add(addReq); err != nil {
		msg, _ := ldap.LDAPResultCodeMap[ldap.LDAPResultEntryAlreadyExists]
		if strings.Contains(err.Error(), msg) {
			return nil
		}
		log.Printf("error adding ou %v: %v", ou, err)
		return err
	}
	return nil
}

// AddGroup adds a group to LDAP
func (lc *ldapClient) AddGroup(group, ou, first, last string) error {
	addReq := ldap.NewAddRequest(fmt.Sprintf("cn=%s,ou=%s,%s", group, ou, lc.base), []ldap.Control{})
	addReq.Attribute("objectClass", []string{"groupOfNames"})
	addReq.Attribute("cn", []string{group})
	addReq.Attribute("member", []string{fmt.Sprintf("cn=%s %s,ou=%s,%s", first, last, ou, lc.base)}) //  'groupOfNames' requires attribute 'member'

	if err := lc.conn.Add(addReq); err != nil {
		msg, _ := ldap.LDAPResultCodeMap[ldap.LDAPResultEntryAlreadyExists]
		if strings.Contains(err.Error(), msg) {
			return nil
		}

		log.Printf("error adding group %v: %v", group, err)
		return err
	}
	return nil
}

// AddUser adds a user to LDAP
func (lc *ldapClient) AddUser(first, last, pwd, ou string) error {
	addReq := ldap.NewAddRequest(fmt.Sprintf("cn=%s %s,ou=%s,%s", first, last, ou, lc.base), []ldap.Control{})
	addReq.Attribute("objectClass", []string{"inetOrgPerson"})
	addReq.Attribute("cn", []string{fmt.Sprintf("%v %v", first, last)})
	addReq.Attribute("sn", []string{last})
	addReq.Attribute("uid", []string{fmt.Sprintf("%c%s", strings.ToLower(first)[0], strings.ToLower(last))})
	addReq.Attribute("userPassword", []string{pwd})

	if err := lc.conn.Add(addReq); err != nil {
		msg, _ := ldap.LDAPResultCodeMap[ldap.LDAPResultEntryAlreadyExists]
		if strings.Contains(err.Error(), msg) {
			return nil
		}

		log.Printf("error adding user %v: %v", first, err)
		return err
	}
	return nil
}

// AddUserToGroup adds a user to an LDAP group
func (lc *ldapClient) AddUserToGroup(first, last, group, ou string) error {
	modReq := ldap.NewModifyRequest(fmt.Sprintf("cn=%s,ou=%s,%s", group, ou, lc.base), []ldap.Control{})
	modReq.Add("member", []string{fmt.Sprintf("cn=%s %s,ou=%s,%s", first, last, ou, lc.base)})

	if err := lc.conn.Modify(modReq); err != nil {
		msg, _ := ldap.LDAPResultCodeMap[ldap.LDAPResultEntryAlreadyExists]
		if strings.Contains(err.Error(), msg) {
			return nil
		}

		log.Printf("error adding user %v: %v", first, err)
		return err
	}
	return nil
}

// Query queries LDAP records
func (lc *ldapClient) Query(delta bool) error {
	filter := fmt.Sprintf("(cn=%s)", ldap.EscapeFilter("Engineering"))
	//filter := "(objectclass=*)" // get everything

	searchReq := ldap.NewSearchRequest(lc.base, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, []string{}, []ldap.Control{})

	result, err := lc.conn.Search(searchReq)
	if err != nil {
		return err
	}

	members := []string{}
	for _, entry := range result.Entries {
		attr := entry.GetAttributeValues("member")
		for _, item := range attr {
			temp := strings.Split(item, ",")[0] //cn=Alice Opa,ou=Users,dc=acme,dc=com
			members = append(members, strings.Split(temp, "=")[1])
		}
	}

	lc.AddMembers(members)

	if delta {
		lc.AddMemberUpdate(members[len(members)-1])
	}
	return nil
}

func (lc *ldapClient) AddMembers(m []string) {
	lc.mtx.Lock()
	defer lc.mtx.Unlock()
	lc.members = m
	lc.revision++
	log.Printf("Current members are: %v. Total %v. Current Revision: %v\n", lc.members, len(lc.members), lc.revision)
}

func (lc *ldapClient) AddMemberUpdate(m string) {
	lc.mtx.Lock()
	defer lc.mtx.Unlock()
	for _, ch := range lc.subscribers {
		u := update{data: m, revision: lc.revision}
		ch <- u
	}

	lc.subscribers = nil
}

func (lc *ldapClient) AddSubscribers(ch chan update) {
	lc.mtx.Lock()
	defer lc.mtx.Unlock()
	lc.subscribers = append(lc.subscribers, ch)
}

func (lc *ldapClient) GetMembers() []string {
	lc.mtx.Lock()
	defer lc.mtx.Unlock()
	return lc.members
}

func (lc *ldapClient) GetRevision() int {
	lc.mtx.Lock()
	defer lc.mtx.Unlock()
	return lc.revision
}

func parsePreferWait(r *http.Request) (time.Duration, error) {
	for _, line := range r.Header.Values("prefer") {
		for _, part := range strings.Split(line, ";") {
			preference := strings.Split(strings.TrimSpace(part), "=")
			if len(preference) == 2 {
				if strings.ToLower(preference[0]) == "wait" {
					n, err := strconv.Atoi(preference[1])
					return time.Duration(n) * time.Second, err
				}
			}
		}
	}
	return 0, nil
}

func parsePreferMode(r *http.Request) []string {
	for _, line := range r.Header.Values("prefer") {
		for _, part := range strings.Split(line, ";") {
			preference := strings.Split(strings.TrimSpace(part), "=")
			if len(preference) == 2 {
				if strings.ToLower(preference[0]) == "modes" {
					return strings.Split(preference[1], ",")
				}
			}
		}
	}
	return []string{}
}

func (s *server) Serve(w http.ResponseWriter, r *http.Request) {

	var clientRevision int

	if h := r.Header.Get("if-none-match"); h != "" {
		var err error
		clientRevision, err = strconv.Atoi(h)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	clientWait, err := parsePreferWait(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	rev := s.lc.GetRevision()

	if !s.deltaMode {
		if clientRevision == 0 || clientRevision != rev {
			log.Printf("client is out-of-date, server revision is %d, sending snapshot bundle...", rev)
			s.writeSnapshotBundle(w, rev)
		} else {
			time.Sleep(clientWait)
			w.Header().Set("Content-Type", "application/vnd.openpolicyagent.bundles")
			w.WriteHeader(304)
		}
	} else {
		if clientRevision == 0 {
			log.Printf("client's first update, server revision is %d, sending snapshot bundle...", rev)
			s.writeSnapshotBundle(w, rev)
		} else {
			ch := make(chan update)

			log.Printf("client is up-to-date, server revision is %d, waiting for change...", rev)
			s.lc.AddSubscribers(ch)

			select {
			case u := <-ch:
				log.Printf("Sending update in delta bundle: %+v\n", u)
				b := bundle.Bundle{
					Manifest: bundle.Manifest{
						Revision: fmt.Sprintf("%d", u.revision),
					},
					Patch: bundle.Patch{
						Data: []bundle.PatchOperation{
							{
								Op:    "upsert",
								Path:  "/members/-",
								Value: u.data,
							},
						},
					},
				}
				w.Header().Set("content-type", "application/vnd.openpolicyagent.bundles")
				w.Header().Set("etag", fmt.Sprintf("%d", u.revision))
				err := bundle.NewWriter(w).Write(b)
				if err != nil {
					log.Printf("error creating delta bundle: %v\n", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			case <-time.After(clientWait):
				w.Header().Set("Content-Type", "application/vnd.openpolicyagent.bundles")
				w.WriteHeader(304)
			}
		}
	}
}

func (s *server) writeSnapshotBundle(w http.ResponseWriter, revision int) {
	module := `package example

	default allow = false
	
	allow {
	  input.member == data.members[_]
	}`

	modulePath := "example/example.rego"

	b := bundle.Bundle{
		Manifest: bundle.Manifest{
			Revision: fmt.Sprintf("%d", revision),
		},
		Data: map[string]interface{}{
			"members": s.lc.GetMembers(),
		},
		Modules: []bundle.ModuleFile{
			{
				URL:    modulePath,
				Path:   modulePath,
				Parsed: ast.MustParseModule(module),
				Raw:    []byte(module),
			},
		},
	}
	w.Header().Set("content-type", "application/vnd.openpolicyagent.bundles")
	w.Header().Set("etag", fmt.Sprintf("%d", revision))
	err := bundle.NewWriter(w).Write(b)
	if err != nil {
		log.Printf("error creating bundle: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func main() {
	client := ldapClient{
		host:         "localhost",
		port:         389,
		base:         "dc=acme,dc=com",
		bindDN:       "cn=admin,dc=acme,dc=com",
		bindPassword: "admin",
		members:      []string{},
	}

	s := &server{lc: &client, deltaMode: true}

	defer s.lc.Close()

	err := doLDAPSetup(s.lc)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		t := time.Tick(time.Second * 5)
		for {
			<-t
			err := createAndAddNewUserToGroup(s.lc)
			if err != nil {
				log.Printf("error adding user to group: %v\n", err)
			}

			err = client.Query(s.deltaMode)
			if err != nil {
				log.Printf("failed to query LDAP: %v", err)
			}
		}
	}()

	http.HandleFunc("/", s.Serve)
	log.Println("Starting Server")
	http.ListenAndServe("localhost:8000", nil)
}

func createAndAddNewUserToGroup(client *ldapClient) error {

	firstList := []string{"Adam", "Alex", "Aaron", "Ben", "Carl", "Dan", "David", "Edward", "Fred", "Frank", "George", "Hal", "Hank", "Ike", "John", "Jackie", "Joe", "Larry", "Monte", "Matthew", "Mona", "Nathan", "Otto", "Pauline", "Peter", "Rai", "Roger", "Steve", "Thomas", "Tim", "Tyra", "Victoria", "Walter"}
	lastList := []string{"Anderson", "Ashwoon", "Aikin", "Bateman", "Bongard", "Bowers", "Boyd", "Cannon", "Cast", "Deitz", "Dewalt", "Ebner", "Frick", "Hancock", "Haworth", "Hesch", "Hoffman", "Kassing", "Knutson", "Lawless", "Lawicki"}

	rand.Seed(time.Now().UnixNano())

	first := firstList[rand.Intn(len(firstList))]
	full := fmt.Sprintf("%v %v", first, rand.Intn(1000000))
	last := lastList[rand.Intn(len(lastList))]

	err := client.AddUser(full, last, "password", "Users")
	if err != nil {
		return err
	}

	// add user to group
	return client.AddUserToGroup(full, last, "Engineering", "Users")
}

func doLDAPSetup(client *ldapClient) error {
	err := client.Bind()
	if err != nil {
		log.Fatal(err)
	}

	// add an OU
	err = client.AddOU("Users")
	if err != nil {
		log.Fatal(err)
	}

	// add a user
	err = client.AddUser("Alice", "Opa", "password", "Users")
	if err != nil {
		log.Fatal(err)
	}

	// add a group
	err = client.AddGroup("Engineering", "Users", "Alice", "Opa")
	if err != nil {
		log.Fatal(err)
	}

	// query records
	err = client.Query(false)
	if err != nil {
		log.Fatal(err)
	}

	return nil
}
