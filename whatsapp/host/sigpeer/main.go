// SPDX-License-Identifier: GPL-3.0-or-later
// (It links go.mau.fi/libsignal, which is GPL-3.0; nothing else in this repo does.)
//
// sigpeer plays "Alice", a WhatsApp-style Signal peer, using go.mau.fi/libsignal
// (the library whatsmeow uses), so test-wa can check the C port against it.
// It reads one command per line on stdin and answers one line on stdout;
// binary values are hex.
//
//	bundle <regid> <ident> <spkid> <spk> <spksig> <opkid|-> <opk|->   start a session to Bob
//	enc <plaintext>       -> pkmsg <ct> | msg <ct>   encrypt to Bob
//	dec <ct>              -> pt <plaintext>          decrypt a SignalMessage from Bob
//	skdm <group>          -> skdm <bytes>            create Alice's sender key for a group
//	genc <group> <pt>     -> skmsg <ct>              group-encrypt
//	ident                 -> ident <pub>             Alice's identity key
//
// It also plays "Carol", who publishes a bundle for the C side to start a
// session with (the sending direction):
//
//	carol [noopk]         -> bundle <regid> <ident> <spkid> <spk> <spksig> <opkid|-> <opk|->
//	cdec pkmsg|msg <ct>   -> pt <plaintext>          Carol decrypts from the C side
//	cenc <plaintext>      -> pkmsg <ct> | msg <ct>   Carol encrypts to the C side
//
// Errors answer "err <text>". The process exits at EOF.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/libsignal/groups"
	"go.mau.fi/libsignal/keys/identity"
	"go.mau.fi/libsignal/keys/prekey"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/serialize"
	"go.mau.fi/libsignal/session"
	"go.mau.fi/libsignal/tests"
	"go.mau.fi/libsignal/util/keyhelper"
	"go.mau.fi/libsignal/util/optional"
)

func key32(s string) ([32]byte, error) {
	var k [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return k, fmt.Errorf("bad 32-byte key %q", s)
	}
	copy(k[:], b)
	return k, nil
}

func main() {
	ctx := context.Background()
	ser := serialize.NewProtoBufSerializer()
	identKP, _ := keyhelper.GenerateIdentityKeyPair()
	reg := keyhelper.GenerateRegistrationID()
	sessions := tests.NewInMemorySession(ser)
	prekeys := tests.NewInMemoryPreKey()
	spks := tests.NewInMemorySignedPreKey()
	idents := tests.NewInMemoryIdentityKey(identKP, reg)
	senderKeys := tests.NewInMemorySenderKey()
	alice := protocol.NewSignalAddress("alice", 1)
	bob := protocol.NewSignalAddress("bob", 1)
	builder := session.NewBuilder(sessions, prekeys, spks, idents, bob, ser)
	cipher := session.NewCipher(builder, bob)
	gbuilder := groups.NewGroupSessionBuilder(senderKeys, ser)
	// The in-memory sender key store is keyed by pointer, so keep one name per group.
	names := map[string]*protocol.SenderKeyName{}
	nameFor := func(group string) *protocol.SenderKeyName {
		if names[group] == nil {
			names[group] = protocol.NewSenderKeyName(group, alice)
		}
		return names[group]
	}

	carolKP, _ := keyhelper.GenerateIdentityKeyPair()
	carolReg := keyhelper.GenerateRegistrationID()
	cPrekeys := tests.NewInMemoryPreKey()
	cSpks := tests.NewInMemorySignedPreKey()
	cAddr := protocol.NewSignalAddress("c", 1)
	cBuilder := session.NewBuilder(tests.NewInMemorySession(ser), cPrekeys, cSpks,
		tests.NewInMemoryIdentityKey(carolKP, carolReg), cAddr, ser)
	cCipher := session.NewCipher(cBuilder, cAddr)
	var nextKeyID uint32 = 40

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	reply := func(format string, a ...any) {
		fmt.Fprintf(out, format+"\n", a...)
		out.Flush()
	}
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) == 0 {
			continue
		}
		err := func() error {
			switch f[0] {
			case "ident":
				pub := identKP.PublicKey().PublicKey().PublicKey()
				reply("ident %x", pub[:])
			case "bundle":
				if len(f) != 8 {
					return fmt.Errorf("bundle wants 7 args")
				}
				regid, _ := strconv.ParseUint(f[1], 10, 32)
				spkid, _ := strconv.ParseUint(f[3], 10, 32)
				ik, err := key32(f[2])
				if err != nil {
					return err
				}
				spk, err := key32(f[4])
				if err != nil {
					return err
				}
				sigb, err := hex.DecodeString(f[5])
				if err != nil || len(sigb) != 64 {
					return fmt.Errorf("bad signature")
				}
				var sig [64]byte
				copy(sig[:], sigb)
				opkID := optional.NewEmptyUint32()
				var opkPub ecc.ECPublicKeyable
				if f[6] != "-" {
					id, _ := strconv.ParseUint(f[6], 10, 32)
					opkID = optional.NewOptionalUint32(uint32(id))
					k, err := key32(f[7])
					if err != nil {
						return err
					}
					opkPub = ecc.NewDjbECPublicKey(k)
				}
				b := prekey.NewBundle(uint32(regid), 1, opkID, uint32(spkid), opkPub, ecc.NewDjbECPublicKey(spk), sig,
					identity.NewKey(ecc.NewDjbECPublicKey(ik)))
				if err := builder.ProcessBundle(ctx, b); err != nil {
					return err
				}
				reply("ok")
			case "enc":
				pt, err := hex.DecodeString(f[1])
				if err != nil {
					return err
				}
				m, err := cipher.Encrypt(ctx, pt)
				if err != nil {
					return err
				}
				t := "msg"
				if m.Type() == protocol.PREKEY_TYPE {
					t = "pkmsg"
				}
				reply("%s %x", t, m.Serialize())
			case "dec":
				ct, err := hex.DecodeString(f[1])
				if err != nil {
					return err
				}
				m, err := protocol.NewSignalMessageFromBytes(ct, ser.SignalMessage)
				if err != nil {
					return err
				}
				pt, err := cipher.Decrypt(ctx, m)
				if err != nil {
					return err
				}
				reply("pt %x", pt)
			case "carol":
				nextKeyID++
				spk, err := keyhelper.GenerateSignedPreKey(carolKP, nextKeyID, ser.SignedPreKeyRecord)
				if err != nil {
					return err
				}
				cSpks.StoreSignedPreKey(ctx, spk.ID(), spk)
				ik := carolKP.PublicKey().PublicKey().PublicKey()
				sp := spk.KeyPair().PublicKey().PublicKey()
				sig := spk.Signature()
				opk := "- -"
				if len(f) < 2 || f[1] != "noopk" {
					nextKeyID++
					pks, err := keyhelper.GeneratePreKeys(int(nextKeyID), int(nextKeyID), ser.PreKeyRecord)
					if err != nil {
						return err
					}
					cPrekeys.StorePreKey(ctx, nextKeyID, pks[0])
					op := pks[0].KeyPair().PublicKey().PublicKey()
					opk = fmt.Sprintf("%d %x", nextKeyID, op[:])
				}
				reply("bundle %d %x %d %x %x %s", carolReg, ik[:], spk.ID(), sp[:], sig[:], opk)
			case "cdec":
				if len(f) != 3 {
					return fmt.Errorf("cdec wants 2 args")
				}
				ct, err := hex.DecodeString(f[2])
				if err != nil {
					return err
				}
				var pt []byte
				if f[1] == "pkmsg" {
					m, err := protocol.NewPreKeySignalMessageFromBytes(ct, ser.PreKeySignalMessage, ser.SignalMessage)
					if err != nil {
						return err
					}
					pt, err = cCipher.DecryptMessage(ctx, m)
					if err != nil {
						return err
					}
				} else {
					m, err := protocol.NewSignalMessageFromBytes(ct, ser.SignalMessage)
					if err != nil {
						return err
					}
					pt, err = cCipher.Decrypt(ctx, m)
					if err != nil {
						return err
					}
				}
				reply("pt %x", pt)
			case "cenc":
				pt, err := hex.DecodeString(f[1])
				if err != nil {
					return err
				}
				m, err := cCipher.Encrypt(ctx, pt)
				if err != nil {
					return err
				}
				t := "msg"
				if m.Type() == protocol.PREKEY_TYPE {
					t = "pkmsg"
				}
				reply("%s %x", t, m.Serialize())
			case "skdm":
				m, err := gbuilder.Create(ctx, nameFor(f[1]))
				if err != nil {
					return err
				}
				reply("skdm %x", m.Serialize())
			case "genc":
				pt, err := hex.DecodeString(f[2])
				if err != nil {
					return err
				}
				gc := groups.NewGroupCipher(gbuilder, nameFor(f[1]), senderKeys)
				m, err := gc.Encrypt(ctx, pt)
				if err != nil {
					return err
				}
				reply("skmsg %x", m.(*protocol.SenderKeyMessage).SignedSerialize())
			default:
				return fmt.Errorf("unknown command %q", f[0])
			}
			return nil
		}()
		if err != nil {
			reply("err %v", strings.ReplaceAll(err.Error(), "\n", " "))
		}
	}
}
