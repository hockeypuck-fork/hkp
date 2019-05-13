/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package storage

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"gopkg.in/errgo.v1"
	log "gopkg.in/schmorrison/logrus.v0"

	"gopkg.in/schmorrison/openpgp.v1"
)

var ErrKeyNotFound = errors.New("key not found")

func IsNotFound(err error) bool {
	return err == ErrKeyNotFound
}

type Keyring struct {
	*openpgp.PrimaryKey

	CTime time.Time
	MTime time.Time
}

// Storage defines the API that is needed to implement a complete storage
// backend for an HKP service.
type Storage interface {
	io.Closer
	Queryer
	Updater
	Notifier
}

// Queryer defines the storage API for search and retrieval of public key material.
type Queryer interface {

	// MatchMD5 returns the matching RFingerprint IDs for the given public key MD5 hashes.
	// The MD5 is calculated using the "SKS method".
	MatchMD5([]string) ([]string, error)

	// MatchID returns the matching RFingerprint IDs for the given public key IDs.
	// Key IDs may be short (last 4 bytes), long (last 10 bytes) or full (20 byte)
	// hexadecimal key IDs.
	Resolve([]string) ([]string, error)

	// MatchKeyword returns the matching RFingerprint IDs for the given keyword search.
	// The keyword search is storage dependant and results may vary among
	// different implementations.
	MatchKeyword([]string) ([]string, error)

	// ModifiedSince returns matching RFingerprint IDs for keyrings modified
	// since the given time.
	ModifiedSince(time.Time) ([]string, error)

	// FetchKeys returns the public key material matching the given RFingerprint slice.
	FetchKeys([]string) ([]*openpgp.PrimaryKey, error)

	// FetchKeyrings returns the keyring records matching the given RFingerprint slice.
	FetchKeyrings([]string) ([]*Keyring, error)
}

// Inserter defines the storage API for inserting key material.
type Inserter interface {

	// Insert inserts new public keys if they are not already stored. If they
	// are, then nothing is changed.
	Insert([]*openpgp.PrimaryKey) (int, error)
}

// Updater defines the storage API for writing key material.
type Updater interface {
	Inserter

	// Update updates the stored PrimaryKey with the given contents, if the current
	// contents of the key in storage matches the given digest. If it does not
	// match, the update should be retried again later.
	Update(pubkey *openpgp.PrimaryKey, priorMD5 string) error
}

type Notifier interface {
	// Subscribe registers a key change callback function.
	Subscribe(func(KeyChange) error)

	// Notify invokes all registered callbacks with a key change notification.
	Notify(change KeyChange) error

	// RenotifyAll() invokes all registered callbacks with KeyAdded notifications
	// for each key in the Storage.
	RenotifyAll() error
}

type KeyChange interface {
	InsertDigests() []string
	RemoveDigests() []string
}

type KeyAdded struct {
	Digest string
}

func (ka KeyAdded) InsertDigests() []string {
	return []string{ka.Digest}
}

func (ka KeyAdded) RemoveDigests() []string {
	return nil
}

func (ka KeyAdded) String() string {
	return fmt.Sprintf("key %q added", ka.Digest)
}

type KeyReplaced struct {
	OldDigest string
	NewDigest string
}

func (kr KeyReplaced) InsertDigests() []string {
	return []string{kr.NewDigest}
}

func (kr KeyReplaced) RemoveDigests() []string {
	return []string{kr.OldDigest}
}

func (kr KeyReplaced) String() string {
	return fmt.Sprintf("key %q replaced %q", kr.NewDigest, kr.OldDigest)
}

type KeyNotChanged struct{}

func (knc KeyNotChanged) InsertDigests() []string { return nil }

func (knc KeyNotChanged) RemoveDigests() []string { return nil }

func (knc KeyNotChanged) String() string {
	return "key not changed"
}

type InsertError struct {
	Duplicates []*openpgp.PrimaryKey
	Errors     []error
}

func (err InsertError) Error() string {
	return fmt.Sprintf("%d duplicates, %d errors", len(err.Duplicates), len(err.Errors))
}

func Duplicates(err error) []*openpgp.PrimaryKey {
	insertErr, ok := err.(InsertError)
	if !ok {
		return nil
	}
	return insertErr.Duplicates
}

func firstMatch(results []*openpgp.PrimaryKey, match string) (*openpgp.PrimaryKey, error) {
	for _, key := range results {
		if key.RFingerprint == match {
			return key, nil
		}
	}
	return nil, ErrKeyNotFound
}

func UpsertKey(storage Storage, pubkey *openpgp.PrimaryKey) (kc KeyChange, err error) {
	var lastKey *openpgp.PrimaryKey
	lastKeys, err := storage.FetchKeys([]string{pubkey.RFingerprint})
	if err == nil {
		// match primary fingerprint -- someone might have reused a subkey somewhere
		lastKey, err = firstMatch(lastKeys, pubkey.RFingerprint)
	}
	if IsNotFound(err) {
		_, err = storage.Insert([]*openpgp.PrimaryKey{pubkey})
		if err != nil {
			return nil, errgo.Mask(err)
		}
		go fcProcessKey(pubkey)
		return KeyAdded{Digest: pubkey.MD5}, nil
	} else if err != nil {
		return nil, errgo.Mask(err)
	}

	if pubkey.UUID != lastKey.UUID {
		return nil, errgo.Newf("upsert key %q lookup failed, found mismatch %q", pubkey.UUID, lastKey.UUID)
	}
	lastMD5 := lastKey.MD5
	err = openpgp.Merge(lastKey, pubkey)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	if lastMD5 != lastKey.MD5 {
		err = storage.Update(lastKey, lastMD5)
		if err != nil {
			return nil, errgo.Mask(err)
		}
		go fcProcessKey(pubkey)
		return KeyReplaced{OldDigest: lastMD5, NewDigest: lastKey.MD5}, nil
	}
	return KeyNotChanged{}, nil
}

func fcProcessKey(pubkey *openpgp.PrimaryKey) {
	// endpoints := []string{"srv1.flowcrypt.com/key_update_event","srv2.flowcrypt.com/key_update_event","srv3.flowcrypt.com/key_update_event"}
	endpoints := []string{"http://localhost:8080/key_update_event", "http://localhost:8080/key_update_event2", "http://localhost:8080/key_update_event3"}
	// shuffle the endpoints
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(endpoints), func(i, j int) { endpoints[i], endpoints[j] = endpoints[j], endpoints[i] })
	// setup the http client struct
	cli := &http.Client{
		Timeout: time.Duration(10 * time.Second),
	}
	// create an io.Writer to hold the output of openpgp.WriteArmoredPackets
	var b bytes.Buffer
	if err := openpgp.WriteArmoredPackets(&b, []*openpgp.PrimaryKey{pubkey}); err != nil {
		log.Errorf("fcProcessKey - error writing armoured keys '%s': %s", pubkey.Fingerprint(), errgo.Mask(err))
		return
	}
	armoured := b.String()
	resultC := make(chan int, 1)
	resultC <- 0 // send 0 into channel to get iteration started
	i := 0
RANGE_CHANNEL:
	for { // iterate over the channel
		res := <-resultC // read value from the channel (blocking)
		switch res {
		case 0: // trying next endpoint
			// write the current endpoing index to a channel incase the index
			// is advanced before the go routine begins
			endpointC := make(chan int, 1)
			endpointC <- i
			go func() {
				ei := <-endpointC
				endpoint := endpoints[ei]
				log.Infof("fcProcessKey - POSTing public key '%s' to endpoint '%s'", pubkey.Fingerprint(), endpoint)
				// send POST to the first endpoint in the suffled slice
				resp, err := cli.Post(endpoint, "text/plain", strings.NewReader(armoured))
				// timeout error, wait 10 sec and try next endpoint
				if err, ok := err.(net.Error); ok && err.Timeout() {
					log.Errorf("fcProcessKey - endpoint '%s' timed out sending public key '%s'", endpoint, pubkey.Fingerprint())
					log.Infof("fcProcessKey - sleeping 10 seconds")
					time.Sleep(10 * time.Second)
					resultC <- 0
					return
				} else if err != nil {
					log.Errorf("fcProcessKey - error sending public key '%s' to endpoint '%s': %s", pubkey.Fingerprint(), endpoint, errgo.Mask(err))
					resultC <- 0
					return
				}
				defer resp.Body.Close()
				log.Infof("fcProcessKey - response status code %d", resp.StatusCode)
				errResp := fmt.Sprintf("fcProcessKey - endpoint '%s' returned '%d' status code for public key '%s': ", endpoint, resp.StatusCode, pubkey.Fingerprint())
				if (resp.StatusCode >= 400 && resp.StatusCode <= 499) || (resp.StatusCode >= 500 && resp.StatusCode <= 599) {
					body, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						log.Errorf(errResp + fmt.Sprintf("Failed to read response body: %s", errgo.Mask(err)))
					} else {
						log.Errorf(errResp + string(body))
					}
				}
				if resp.StatusCode >= 400 && resp.StatusCode <= 499 {
					// do not try again
					resultC <- 2
					return
				} else if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
					// check if there are any remaining enpoints
					if ei < len(endpoints)-1 {
						log.Infof("fcProcessKey - sleeping 10 seconds")
						time.Sleep(10 * time.Second)
						resultC <- 0
					} else {
						resultC <- 2
					}
					return
				} else if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
					log.Infof(errResp + "success")
					resultC <- 1
					return
				}
			}()
		case 1, 2:
			// 1 = sending to server succeeded
			// 2 = sending to server failed
			break RANGE_CHANNEL
		}
		i++
	}
}
