package doubleratchet

import (
	"bytes"
	"fmt"
	"encoding/hex"
)

// Session of the party involved in the Double Ratchet Algorithm.
type Session interface {
	// RatchetEncrypt performs a symmetric-key ratchet step, then AEAD-encrypts the message with
	// the resulting message key.
	RatchetEncrypt(plaintext, associatedData []byte) (Message, error)

	// RatchetDecrypt is called to AEAD-decrypt messages.
	RatchetDecrypt(m Message, associatedData []byte) ([]byte, error)

	RatchetEncryptHE(plaintext, associatedData []byte) (MessageHE, error)

	// RatchetDecrypt is called to AEAD-decrypt messages.
	RatchetDecryptHE(m MessageHE, associatedData []byte) ([]byte, error)

	//DeleteMk remove a message key from the database
	DeleteMk(Key, uint32) error
}

type sessionState struct {
	id []byte
	State
	storage SessionStorage
}

// New creates session with the shared key.
func New(id []byte, sharedKey Key, keyPair DHPair, storage SessionStorage, opts ...option) (Session, error) {
	state, err := newState(sharedKey, opts...)
	if err != nil {
		return nil, err
	}
	state.DHs = keyPair

	session := &sessionState{id: id, State: state, storage: storage}

	return session, session.store()
}

// New creates session with the shared key. Bob
func NewHE(id []byte, sharedKey Key, sharedHKA Key, sharedHKB Key, keyPair DHPair, storage SessionStorage, opts ...option) (Session, error) {
	state, err := newState(sharedKey, opts...)
	if err != nil {
		return nil, err
	}
	state.DHs = keyPair
	state.HKs = nil
	state.NHKs = sharedHKB
	state.HKr = nil
	state.NHKr = sharedHKA

	session := &sessionState{id: id, State: state, storage: storage}

	return session, session.store()
}

// NewWithRemoteKey creates session with the shared key and public key of the other party. Alice
func NewWithRemoteKeyHE(id []byte, sharedKey, sharedHKA Key, sharedHKB Key, remoteKey Key, storage SessionStorage, opts ...option) (Session, error) {
	state, err := newState(sharedKey, opts...)
	if err != nil {
		return nil, err
	}
	state.DHs, err = state.Crypto.GenerateDH()
	if err != nil {
		return nil, fmt.Errorf("can't generate key pair: %s", err)
	}
	state.DHr = remoteKey
	secret, err := state.Crypto.DH(state.DHs, state.DHr)
	if err != nil {
		return nil, fmt.Errorf("can't generate dh secret: %s", err)
	}

	state.SendCh, state.NHKs = state.RootCh.step(secret)

	state.HKs = sharedHKA
	state.HKr = nil
	state.NHKr = sharedHKB

	session := &sessionState{id: id, State: state, storage: storage}

	return session, session.store()
}

// NewWithRemoteKey creates session with the shared key and public key of the other party.
func NewWithRemoteKey(id []byte, sharedKey, remoteKey Key, storage SessionStorage, opts ...option) (Session, error) {
	state, err := newState(sharedKey, opts...)
	if err != nil {
		return nil, err
	}
	state.DHs, err = state.Crypto.GenerateDH()
	if err != nil {
		return nil, fmt.Errorf("can't generate key pair: %s", err)
	}
	state.DHr = remoteKey
	secret, err := state.Crypto.DH(state.DHs, state.DHr)
	if err != nil {
		return nil, fmt.Errorf("can't generate dh secret: %s", err)
	}

	state.SendCh, _ = state.RootCh.step(secret)

	session := &sessionState{id: id, State: state, storage: storage}

	return session, session.store()
}

// Load a session from a SessionStorage implementation and apply options.
func Load(id []byte, store SessionStorage, opts ...option) (Session, error) {
	state, err := store.Load(id)
	if err != nil {
		return nil, err
	}

	if state == nil {
		return nil, nil
	}

	if err = state.applyOptions(opts); err != nil {
		return nil, err
	}

	s := &sessionState{id: id, State: *state}
	s.storage = store

	return s, nil
}

func (s *sessionState) store() error {
	if s.storage != nil {
		err := s.storage.Save(s.id, &s.State)
		if err != nil {
			return err
		}
	}
	return nil
}

// RatchetEncrypt performs a symmetric-key ratchet step, then encrypts the message with
// the resulting message key.
func (s *sessionState) RatchetEncrypt(plaintext, ad []byte) (Message, error) {
	var (
		h = MessageHeader{
			DH: s.DHs.PublicKey(),
			N:  s.SendCh.N,
			PN: s.PN,
		}
		mk = s.SendCh.step()
	)
	ct, err := s.Crypto.Encrypt(mk, plaintext, append(ad, h.Encode()...))
	if err != nil {
		return Message{}, err
	}

	// Store state
	if err := s.store(); err != nil {
		return Message{}, err
	}

	return Message{h, ct}, nil
}

func (s *sessionState) RatchetEncryptHE(plaintext, ad []byte) (MessageHE, error) {
	var (
		h = MessageHeader{
			DH: s.DHs.PublicKey(),
			N:  s.SendCh.N,
			PN: s.PN,
		}

		mk = s.SendCh.step()
	)

	he, err := s.Crypto.Encrypt(s.HKs, h.Encode(), ad)

	if err != nil {
		return MessageHE{}, err
	}

	ct, err := s.Crypto.Encrypt(mk, plaintext, append(ad, he...))

	if err != nil {
		return MessageHE{}, err
	}

	// Store state
	if err := s.store(); err != nil {
		return MessageHE{}, err
	}

	return MessageHE{Header: he, Ciphertext: ct}, nil
}
func (s *sessionState) DecryptHeader(m1 MessageHE) ([]byte, bool, error) {

	h, err := s.Crypto.Decrypt(s.HKr, m1.Header, nil)
	if err == nil {
		return h, false, nil
	}

	h, err = s.Crypto.Decrypt(s.NHKr, m1.Header, nil)
	if err != nil {
		return nil, false, err
	}

	return h, true, err
}

func (s *sessionState) TrySkippedMessageKeysHE(m1 MessageHE, ad []byte) ([]byte, error) {

	// this .All() should be redone in a more conducive manner
	key_pairs, _ := s.MkSkipped.All()

	for raw_hk, keys := range(key_pairs) {
		for n, mk := range(keys) {
			hk, _ := hex.DecodeString(raw_hk)
			h, err := s.Crypto.Decrypt(hk, m1.Header, ad)

			if err != nil {
				continue
			}

			he, _ := MessageEncHeader(h).Decode()

			if he.N == uint32(n) {
				plaintext, err := s.Crypto.Decrypt(mk, m1.Ciphertext, append(ad, m1.Header...))
				if err != nil {
					return nil, err
				}
				_ = s.MkSkipped.DeleteMk(hk, n)
				return plaintext, nil
			}
		}
	}
	return nil, nil
}

// RatchetDecrypt is called to decrypt messages.
func (s *sessionState) RatchetDecryptHE(m1 MessageHE, ad []byte) ([]byte, error) {

	text, err := s.TrySkippedMessageKeysHE(m1, ad)
	if err == nil && text != nil {
		return text, nil
	}

	h, dh_ratchet, err := s.DecryptHeader(m1)

	if err != nil {
		return nil, err
	}

	h1, err := MessageEncHeader(h).Decode()

	if err != nil {
		return nil, err
	}

	m := Message{h1, m1.Ciphertext}

	var (
		// All changes must be applied on a different session object, so that this session won't be modified nor left in a dirty session.
		sc = s.State

		skippedKeys1 []skippedKey
		skippedKeys2 []skippedKey
	)

	if dh_ratchet {

		if skippedKeys1, err = sc.skipMessageKeys(sc.HKr, uint(m.Header.PN)); err != nil {
			return nil, fmt.Errorf("can't skip previous chain message keys: %s", err)
		}

		if err = sc.dhRatchet(m.Header); err != nil {
			return nil, fmt.Errorf("can't perform ratchet step: %s", err)
		}
	}

	// After all, update the current chain.
	if skippedKeys2, err = sc.skipMessageKeys(sc.HKr, uint(m.Header.N)); err != nil {
		return nil, fmt.Errorf("can't skip current chain message keys: %s", err)
	}

	mk := sc.RecvCh.step()

	plaintext, err := s.Crypto.Decrypt(mk, m.Ciphertext, append(ad, m1.Header...))
	if err != nil {
		return nil, fmt.Errorf("can't decrypt: %s", err)
	}

	skippedKeys := append(skippedKeys1, skippedKeys2...)
	//sc.KeysCount++

	// Apply changes.
	if err := s.applyChanges(sc, s.id, skippedKeys); err != nil {
		return nil, err
	}

	// Store state
	if err := s.store(); err != nil {
		return nil, err
	}

	s.truncateKeys()

	return plaintext, nil
}

// DeleteMk deletes a message key
func (s *sessionState) DeleteMk(dh Key, n uint32) error {
	return s.MkSkipped.DeleteMk(dh, uint(n))
}

// RatchetDecrypt is called to decrypt messages.
func (s *sessionState) RatchetDecrypt(m Message, ad []byte) ([]byte, error) {
	// Is the message one of the skipped?
	mk, ok, err := s.MkSkipped.Get(m.Header.DH, uint(m.Header.N))
	if err != nil {
		return nil, err
	}

	if ok {
		plaintext, err := s.Crypto.Decrypt(mk, m.Ciphertext, append(ad, m.Header.Encode()...))
		if err != nil {
			return nil, fmt.Errorf("can't decrypt skipped message: %s", err)
		}
		if err := s.store(); err != nil {
			return nil, err
		}
		return plaintext, nil
	}

	var (
		// All changes must be applied on a different session object, so that this session won't be modified nor left in a dirty session.
		sc = s.State

		skippedKeys1 []skippedKey
		skippedKeys2 []skippedKey
	)

	// Is there a new ratchet key?
	if !bytes.Equal(m.Header.DH, sc.DHr) {
		if skippedKeys1, err = sc.skipMessageKeys(sc.DHr, uint(m.Header.PN)); err != nil {
			return nil, fmt.Errorf("can't skip previous chain message keys: %s", err)
		}
		if err = sc.dhRatchet(m.Header); err != nil {
			return nil, fmt.Errorf("can't perform ratchet step: %s", err)
		}
	}

	// After all, update the current chain.
	if skippedKeys2, err = sc.skipMessageKeys(sc.DHr, uint(m.Header.N)); err != nil {
		return nil, fmt.Errorf("can't skip current chain message keys: %s", err)
	}
	mk = sc.RecvCh.step()
	plaintext, err := s.Crypto.Decrypt(mk, m.Ciphertext, append(ad, m.Header.Encode()...))
	if err != nil {
		return nil, fmt.Errorf("can't decrypt: %s", err)
	}

	// Append current key, waiting for confirmation
	skippedKeys := append(skippedKeys1, skippedKeys2...)
	skippedKeys = append(skippedKeys, skippedKey{
		key: sc.DHr,
		nr:  uint(m.Header.N),
		mk:  mk,
		seq: sc.KeysCount,
	})

	// Increment the number of keys
	sc.KeysCount++

	// Apply changes.
	if err := s.applyChanges(sc, s.id, skippedKeys); err != nil {
		return nil, err
	}

	// Store state
	if err := s.store(); err != nil {
		return nil, err
	}

	return plaintext, nil
}
