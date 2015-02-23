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

package mock

import (
	"time"

	"gopkg.in/hockeypuck/openpgp.v0"

	"gopkg.in/hockeypuck/hkp.v0/storage"
)

type MethodCall struct {
	Name string
	Args []interface{}
}

type Recorder struct {
	Calls []MethodCall
}

func (m *Recorder) record(name string, args ...interface{}) {
	m.Calls = append(m.Calls, MethodCall{Name: name, Args: args})
}

func (m *Recorder) MethodCount(name string) int {
	var n int
	for _, call := range m.Calls {
		if name == call.Name {
			n++
		}
	}
	return n
}

type resolverFunc func([]string) ([]string, error)
type modifiedSinceFunc func(time.Time) ([]string, error)
type fetchKeysFunc func([]string) ([]*openpgp.Pubkey, error)
type fetchKeyringsFunc func([]string) ([]*storage.Keyring, error)
type insertFunc func([]*openpgp.Pubkey) error
type updateFunc func(*openpgp.Pubkey) error

type Storage struct {
	Recorder
	matchMD5      resolverFunc
	resolve       resolverFunc
	matchKeyword  resolverFunc
	modifiedSince modifiedSinceFunc
	fetchKeys     fetchKeysFunc
	fetchKeyrings fetchKeyringsFunc
	insert        insertFunc
	update        updateFunc

	notified []func(storage.KeyChange) error
}

type Option func(*Storage)

func MatchMD5(f resolverFunc) Option { return func(m *Storage) { m.matchMD5 = f } }
func Resolve(f resolverFunc) Option  { return func(m *Storage) { m.resolve = f } }
func MatchKeyword(f resolverFunc) Option {
	return func(m *Storage) { m.matchKeyword = f }
}
func ModifiedSince(f modifiedSinceFunc) Option {
	return func(m *Storage) { m.modifiedSince = f }
}
func FetchKeys(f fetchKeysFunc) Option { return func(m *Storage) { m.fetchKeys = f } }
func FetchKeyrings(f fetchKeyringsFunc) Option {
	return func(m *Storage) { m.fetchKeyrings = f }
}
func Insert(f insertFunc) Option { return func(m *Storage) { m.insert = f } }
func Update(f updateFunc) Option { return func(m *Storage) { m.update = f } }

func NewStorage(options ...Option) *Storage {
	m := &Storage{}
	for _, option := range options {
		option(m)
	}
	return m
}

func (m *Storage) MatchMD5(s []string) ([]string, error) {
	m.record("MatchMD5", s)
	if m.matchMD5 != nil {
		return m.matchMD5(s)
	}
	return nil, nil
}
func (m *Storage) Resolve(s []string) ([]string, error) {
	m.record("Resolve", s)
	if m.resolve != nil {
		return m.resolve(s)
	}
	return nil, nil
}
func (m *Storage) MatchKeyword(s []string) ([]string, error) {
	m.record("MatchKeyword", s)
	if m.matchKeyword != nil {
		return m.matchKeyword(s)
	}
	return nil, nil
}
func (m *Storage) ModifiedSince(t time.Time) ([]string, error) {
	m.record("ModifiedSince", t)
	if m.modifiedSince != nil {
		return m.modifiedSince(t)
	}
	return nil, nil
}
func (m *Storage) FetchKeys(s []string) ([]*openpgp.Pubkey, error) {
	m.record("FetchKeys", s)
	if m.fetchKeys != nil {
		return m.fetchKeys(s)
	}
	return nil, nil
}
func (m *Storage) FetchKeyrings(s []string) ([]*storage.Keyring, error) {
	m.record("FetchKeyrings", s)
	if m.fetchKeyrings != nil {
		return m.fetchKeyrings(s)
	}
	return nil, nil
}
func (m *Storage) Insert(keys []*openpgp.Pubkey) error {
	m.record("Insert", keys)
	if m.insert != nil {
		return m.insert(keys)
	}
	return nil
}
func (m *Storage) Update(key *openpgp.Pubkey) error {
	m.record("Update", key)
	if m.insert != nil {
		return m.update(key)
	}
	return nil
}
func (m *Storage) Subscribe(f func(storage.KeyChange) error) {
	m.notified = append(m.notified, f)
}
func (m *Storage) Notify(change storage.KeyChange) error {
	for _, cb := range m.notified {
		err := cb(change)
		if err != nil {
			return err
		}
	}
	return nil
}