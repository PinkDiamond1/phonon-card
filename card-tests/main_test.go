package cardtests

import (
	"errors"
	"fmt"
	"testing"

	"github.com/GridPlus/phonon-client/cert"
	"github.com/GridPlus/phonon-client/model"
	"github.com/GridPlus/phonon-client/orchestrator"
	"github.com/GridPlus/phonon-client/tlv"
	"github.com/GridPlus/phonon-client/util"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

//global todo:
// add errors by their type as defined in the client code instead of strings

const maxPhononStorageAmount = 256

func TestSelect(t *testing.T) {
	cs := getCardHappy()
	_, _, _, err := cs.Select()
	if err != nil {
		t.Error("Unable to select card")
		t.FailNow()
	}
}

func TestInstallCert(t *testing.T) {
	//reset state
	cs := selectHappy()
	//todo: install invalid cert
	err := cs.InstallCertificate(cert.SignWithDemoKey)
	if err != nil {
		t.Error("unable to install demo key" + err.Error())
		t.FailNow()

	}
	err = cs.InstallCertificate(cert.SignWithDemoKey)
	//todo: replace this error with card cert already installed err
	if err != nil && err.Error() != "Certificate already loaded" {
		if err != nil {
			t.Error("failed install cert test: should have received cert already received error, but received error:" + err.Error())
			t.FailNow()
		} else {
			t.Error("failed install cert test: should have received cert already received error, but received no error")
			t.FailNow()
		}

	}
}

func TestPairToTerminal(t *testing.T) {
	cs := setPinHappy()
	_, err := cs.Pair()
	if err != nil {
		t.Error("Unable to pair to terminal" + err.Error())
		t.FailNow()
	}
}

func TestSetPin(t *testing.T) {
	//reset state
	cs := installCertHappy()
	err := cs.Init("")
	if err == nil {
		t.Error("Pin of length 0 should have failed")
		t.FailNow()

	}
	err = cs.Init("1111111")
	if err == nil {
		t.Error("Pin of length 7 should have failed")
		t.FailNow()

	}
	err = cs.Init("😀🖕🏿")
	if err == nil {
		t.Error("Shouldn't be able to set emoji pin")
		t.FailNow()
	}
	err = cs.Init("abcdef")
	if err == nil {
		t.Error("Shouldn't be able to set letters as pin")
		t.FailNow()
	}
	err = cs.Init("111111")
	if err != nil {
		t.Error("Unable to set pin: " + err.Error())
		t.FailNow()

	}
	err = cs.Init("123321")
	if err == nil {
		t.Error("Shouldn't be able to set new pin. Pin already set")
		t.FailNow()
	}
}

func TestUnlockPin(t *testing.T) {
	cs := setPinHappy()
	err := cs.OpenSecureConnection()
	if err != nil {
		t.Error("unable to pair with card: ", err.Error())
		t.FailNow()
	}
	err = cs.VerifyPIN("111112")
	if err == nil && err.Error() != "Pin Verification Failed" {
		if err != nil {
			t.Error("Incorrect pin didn't return proper error. Returned: " + err.Error())
			t.FailNow()
		} else {
			t.Error("Incorrect pin didn't return error")
			t.FailNow()
		}

	}

	// one too long
	err = cs.VerifyPIN("1111111")
	if err == nil && err.Error() != "Pin Verification Failed" {
		if err != nil {
			t.Error("Incorrect pin didn't return proper error. Returned: " + err.Error())
			t.FailNow()
		} else {
			t.Error("Incorrect pin didn't return error")
			t.FailNow()
		}

	}
	// no pin entered
	err = cs.VerifyPIN("")
	if err == nil && err.Error() != "Pin Verification Failed" {
		if err != nil {
			t.Error("Incorrect pin didn't return proper error. Returned: " + err.Error())
			t.FailNow()
		} else {
			t.Error("Incorrect pin didn't return error")
			t.FailNow()
		}

	}

	// correct pin
	err = cs.VerifyPIN("111111")
	if err != nil {
		t.Error("Unable to verify pin" + err.Error())
		t.FailNow()

	}
	pinRetries := 10
	_, _, initialized, err := cs.Select()
	if err != nil {
		t.Error("unable to select card after unlocking with pin: " + err.Error())
		t.FailNow()
	}
	if !initialized {
		t.Error("card should be shown as initialized, but isnt")
		t.FailNow()
	}
	err = cs.OpenSecureChannel()
	if err != nil {
		t.Error("unable to open secure channel: " + err.Error())
		t.FailNow()
	}
	for i := 0; i < pinRetries; i++ {
		err = cs.VerifyPIN("222222")
		if err == nil {
			t.Error("Wrong pin didn't return error")
			t.FailNow()
		}
	}
	// correct pin shouldn't work after max_retries failures
	err = cs.VerifyPIN("111111")
	if err == nil {
		t.Error("Pin wasn't locked after max_retries met")
		t.FailNow()
	}

}

func TestChangePin(t *testing.T) {
	cs := setPinHappy()
	err := cs.OpenSecureConnection()
	if err != nil {
		t.Error("Unable to open secure connection to card: " + err.Error())
		t.FailNow()
	}
	err = cs.VerifyPIN("111111")
	if err != nil {
		t.Error("Unable to verify pin: " + err.Error())
		t.FailNow()
	}
	//todo: probably verify pin now
	err = cs.ChangePIN("")
	if err == nil {
		t.Error("ChangePin should have failed on empty pin")
		t.FailNow()
	}
	err = cs.ChangePIN("1111111")
	if err == nil {
		t.Error("ChangePin should have failed on too long pin")
		t.FailNow()
	}
	err = cs.ChangePIN("abcdef")
	if err == nil {
		t.Error("ChangePin should have failed on non-numeric pin")
		t.FailNow()
	}
	err = cs.ChangePIN("111111")
	if err != nil {
		t.Error("Changing pin to already set pin returned error: " + err.Error())
		t.FailNow()
	}
	err = cs.ChangePIN("222222")
	if err != nil {
		t.Error("Unable to change pin properly: " + err.Error())
		t.FailNow()

	}
	err = cs.VerifyPIN("222222")
	if err != nil {
		t.Error("unable to verify pin after changing it: " + err.Error())
		t.FailNow()

	}

	err = cs.OpenSecureConnection()
	if err != nil {
		t.Error("Unable to open secure connection to card: " + err.Error())
		t.FailNow()
	}

	err = cs.VerifyPIN("222222")
	if err != nil {
		t.Error("unable to verify pin after changing it: " + err.Error())
		t.FailNow()

	}
}

func TestCreatePhonon(t *testing.T) {
	cs := unlockHappy()
	_, _, err := cs.CreatePhonon(model.Secp256k1)
	if err != nil {
		t.Error("Unable to create a phonon: " + err.Error())
		t.FailNow()

	}
	_, _, err = cs.CreatePhonon(28)
	if err == nil {
		t.Error("no error upon creating phonon with unimplemented curve type")
		t.FailNow()

	}
	//todo: attempting to create with curve type for native phonon should fail
}

func TestCreateAsManyPhononsAsPossible(t *testing.T) {
	cs := unlockHappy()
	var createdIndices []uint16
	for i := 0; i < maxPhononStorageAmount; i++ {

		keyIndex, _, err := cs.CreatePhonon(model.Secp256k1)
		if err != nil {
			t.Error(err)
			t.FailNow()
			return
		}
		createdIndices = append(createdIndices, keyIndex)
	}
	// list phonons doesn't work. likely runs out of memory determining which phonons to return
	list, err := cs.ListPhonons(model.Unspecified, 0, 0)
	if err != nil {
		t.Error(err)
		t.FailNow()
		return
	}
	//Check that all phonons created were listed
	if len(list) != maxPhononStorageAmount {
		t.Error(err)
		t.FailNow()
		return
	}
	//Clean up all phonons before next test
	for _, keyIndex := range createdIndices {
		_, err := cs.DestroyPhonon(keyIndex)
		if err != nil {
			t.Error("unable to delete phonon at keyIndex ", keyIndex)
			t.FailNow()
			t.Error(err)
			t.FailNow()
			return
		}
	}
}

func TestSetDescriptor(t *testing.T) {
	type phononAndExpectedError struct {
		testPhonon  *model.Phonon
		expectedErr error
	}
	regulartlv, err := tlv.NewTLV(0x69, []byte("test"))
	if err != nil {

	}
	testPhonons := []phononAndExpectedError{
		// bitcoin
		{
			testPhonon: &model.Phonon{
				Denomination: model.Denomination{
					Base:     1,
					Exponent: 1,
				},
				CurrencyType: model.Bitcoin,
			},
			expectedErr: nil,
		},
		// eth
		{
			testPhonon: &model.Phonon{
				Denomination: model.Denomination{
					Base:     1,
					Exponent: 1,
				},
				CurrencyType: model.Ethereum,
			},
			expectedErr: nil,
		},
		// unspecified
		{
			testPhonon: &model.Phonon{
				Denomination: model.Denomination{
					Base:     1,
					Exponent: 1,
				},
				CurrencyType: model.Unspecified,
			},
			expectedErr: nil,
		},
		//	out of bounds currency type doesn't currently work on card
		{
			testPhonon: &model.Phonon{
				Denomination: model.Denomination{
					Base:     1,
					Exponent: 1,
				},
				CurrencyType: 256,
			},
			expectedErr: nil,
		},
		// top bound currency type should work fine
		{
			testPhonon: &model.Phonon{
				Denomination: model.Denomination{
					Base:     1,
					Exponent: 1,
				},
				CurrencyType: 255,
			},
			expectedErr: nil,
		},
		// nonexistent phonon
		{
			testPhonon: &model.Phonon{
				KeyIndex: 100,
				Denomination: model.Denomination{
					Base:     1,
					Exponent: 1,
				},
				CurrencyType: model.Bitcoin,
			},
			expectedErr: errors.New("phonon index invalid"),
		},
		// out of bounds Key index
		{
			testPhonon: &model.Phonon{
				KeyIndex: maxPhononStorageAmount + 5,
				Denomination: model.Denomination{
					Base:     1,
					Exponent: 1,
				},
				CurrencyType: model.Bitcoin,
			},
			expectedErr: errors.New("phonon index invalid"),
		},
		// max denomination
		{
			testPhonon: &model.Phonon{
				Denomination: model.Denomination{
					Base:     255,
					Exponent: 255,
				},
				CurrencyType: model.Bitcoin,
			},
			expectedErr: nil,
		},
		// tlv
		{
			testPhonon: &model.Phonon{
				Denomination: model.Denomination{
					Base:     1,
					Exponent: 1,
				},
				CurrencyType: model.Bitcoin,
				ExtendedTLV:  []tlv.TLV{regulartlv},
			},
			expectedErr: nil,
		},
		// schema version max
		{
			testPhonon: &model.Phonon{
				Denomination: model.Denomination{
					Base:     1,
					Exponent: 1,
				},
				CurrencyType:  model.Bitcoin,
				SchemaVersion: 255,
			},
			expectedErr: nil,
		},
		// extended schema version max
		{
			testPhonon: &model.Phonon{
				Denomination: model.Denomination{
					Base:     1,
					Exponent: 1,
				},
				CurrencyType:          model.Bitcoin,
				ExtendedSchemaVersion: 255,
			},
			expectedErr: nil,
		},
		// extended field limits
		{
			testPhonon: &model.Phonon{
				Denomination: model.Denomination{
					Base:     1,
					Exponent: 1,
				},
				CurrencyType: model.Bitcoin,
			},
			expectedErr: nil,
		},
		//todo: verify and review memory allocation for phonon storage
	}
	cs := createPhononHappy(len(testPhonons))
	t.Log(fmt.Sprintf("creating %d phonons", len(testPhonons)))
	for index, testPhononAndErr := range testPhonons {
		if testPhononAndErr.testPhonon.KeyIndex == 0 {
			//index starts at 1 on card
			testPhononAndErr.testPhonon.KeyIndex = uint16(index + 1)
		}
		err := cs.SetDescriptor(testPhononAndErr.testPhonon)
		if err == nil && testPhononAndErr.expectedErr != nil {
			t.Error(fmt.Sprintf("descriptor set for phonon: %+v : but should have gotten error: %s", *testPhononAndErr.testPhonon, testPhononAndErr.expectedErr.Error()))
			t.FailNow()

		} else if err != nil && testPhononAndErr.expectedErr == nil {
			t.Error(fmt.Sprintf("Unable to set descriptor for: %+v received error: %s", *testPhononAndErr.testPhonon, err.Error()))
			t.FailNow()

		} else if err != nil && err.Error() != testPhononAndErr.expectedErr.Error() {
			t.Error(fmt.Sprintf("Wrong error from set Descriptor for phonon: %+v. Received: %s, Expected: %s", *testPhononAndErr.testPhonon, err.Error(), testPhononAndErr.expectedErr.Error()))
			t.FailNow()

		}
	}
}

func TestDestroyPhonon(t *testing.T) {
	cs := setDescriptorHappy(5)
	pubKey, err := cs.GetPhononPubKey(uint16(1), model.Secp256k1)
	if err != nil {
		t.Error("Unable to get phonon pubkey: " + err.Error())
		t.FailNow()

	}
	privKey, err := cs.DestroyPhonon(uint16(1))
	if err != nil {
		t.Error("Unable to get phonon privateKey: " + err.Error())
		t.FailNow()

	}
	destroyedPubKey, err := model.NewPhononPubKey(ethcrypto.FromECDSAPub(&privKey.PublicKey), model.Secp256k1)
	if !destroyedPubKey.Equal(pubKey) {
		t.Error("PrivateKey and public key do not match after destroy phonon operation")
		t.FailNow()

	}
	_, err = cs.DestroyPhonon(69)
	fmt.Println(err.Error())
	if err == nil || err.Error() != "Phonon index invalid" {
		if err != nil {
			t.Error("did not receive proper error on delete phonon where phonon is out of range")
			t.FailNow()
		} else {
			t.Error("Did not recive error on delete phonon where phonon is out of range")
			t.FailNow()
		}

	}
	_, err = cs.DestroyPhonon(maxPhononStorageAmount + 5)
	if err == nil || err.Error() != "Phonon index invalid" {
		if err != nil {
			t.Error("did not receive proper error on delete phonon where phonon is out of range: ", err.Error())
			t.FailNow()
		} else {
			t.Error("Did not recive error on delete phonon where phonon is out of range")
			t.FailNow()
		}

	}
	//todo: create max amount of phonons and delete the last one
	//todo: delete from properly deleted spot
	//todo: delete from index zero
	//todo: native phonons should work
	//todo: test destroy of phonon with unsupported curve
}

func TestCardPairEz(t *testing.T) {
	cs := setPinHappy()
	term := orchestrator.NewPhononTerminal()
	card, err := orchestrator.NewSession(cs)
	if err != nil {
		t.Error("Unable to generate sesison from command set: " + err.Error())
		t.FailNow()

	}
	term.AddSession(card)
	// todo: test attempting to pair without pin verification
	err = card.VerifyPIN("111111")
	if err != nil {
		t.Error("Unable to verify pin on card: " + err.Error())
		t.FailNow()
	}

	mockid, err := term.GenerateMock()
	if err != nil {
		t.Error(err.Error())
		t.FailNow()

	}
	mock := term.SessionFromID(mockid)
	mock.VerifyPIN("111111")

	err = mock.ConnectToLocalProvider()
	if err != nil {
		t.Error("Unable to connect mock to local provider: " + err.Error())
		t.FailNow()

	}

	err = card.ConnectToLocalProvider()
	if err != nil {
		t.Error("Unable to connect card to local provider: " + err.Error())
		t.FailNow()

	}

	err = mock.ConnectToCounterparty(card.GetName())
	if err != nil {
		t.Error("Unable to pair with local mock: " + err.Error())
		t.FailNow()

	}

	//send to prove paring
	err = card.ConnectToCounterparty(mockid)
	if err != nil {
		t.Error("Unable to pair with local mock: " + err.Error())
		t.FailNow()

	}
	//send to prove pairing
}

func TestCardPairReal(t *testing.T) {
	cs := setPinHappy()
	term := orchestrator.NewPhononTerminal()
	card, err := orchestrator.NewSession(cs)
	if err != nil {
		t.Error("Unable to generate sesison from command set: " + err.Error())
		t.FailNow()

	}
	// todo: test attempting to pair without pin verification
	card.VerifyPIN("111111")
	mockid, err := term.GenerateMock()
	if err != nil {
		t.Error(err.Error())
		t.FailNow()

	}
	mock := term.SessionFromID(mockid)
	mock.VerifyPIN("111111")
	err = mock.ConnectToLocalProvider()
	if err != nil {
		t.Error("Unable to connect mock to local provider: " + err.Error())
		t.FailNow()

	}
	err = card.ConnectToLocalProvider()
	if err != nil {
		t.Error("Unable to connect card to local provider: " + err.Error())
		t.FailNow()

	}
	err = mock.ConnectToCounterparty(card.GetName())
	if err != nil {
		t.Error("Unable to pair with local mock: " + err.Error())
		t.FailNow()

	}
	//send to prove paring
	index, _, err := card.CreatePhonon()
	if err != nil {
		t.Error("Unable to create phonon to prove pairing worked: " + err.Error())
		t.FailNow()
	}
	err = card.SetDescriptor(&model.Phonon{
		KeyIndex: index,
		Denomination: model.Denomination{
			Base:     1,
			Exponent: 1,
		},
		CurrencyType: 1,
	})
	if err != nil {
		t.Error("Unable to set descriptor on test phonon for sending: " + err.Error())
		t.FailNow()
	}
	err = card.SendPhonons([]uint16{index})
	if err != nil {
		t.Error("Unable to send phonons to prove pairing: " + err.Error())
		t.FailNow()
	}
	err = card.ConnectToCounterparty(mockid)
	if err != nil {
		t.Error("Unable to pair with local mock: " + err.Error())
		t.FailNow()

	}

	// steal phononCommandSet tests in client code
	mock2id, err := term.GenerateMock()
	if err != nil {
		t.Errorf("Unable to generate session from command set: %s", err.Error())
		t.FailNow()
	}
	mock2 := term.SessionFromID(mock2id)
	err = mock.ConnectToLocalProvider()
	if err != nil {
		t.Error("Unable to connect mock to local provider: " + err.Error())
		t.FailNow()
	}
	err = mock2.ConnectToCounterparty(card.GetName())
	if err != nil {
		t.Error("Unable to pair with second local mock: " + err.Error())
		t.FailNow()
	}
	//send to prove paring
	index, _, err = card.CreatePhonon()
	if err != nil {
		t.Error("Unable to create phonon to prove pairing worked: " + err.Error())
		t.FailNow()
	}
	err = card.SetDescriptor(&model.Phonon{
		KeyIndex: index,
		Denomination: model.Denomination{
			Base:     1,
			Exponent: 1,
		},
		CurrencyType: 1,
	})
	if err != nil {
		t.Error("Unable to set descriptor on test phonon for sending: " + err.Error())
		t.FailNow()
	}
	err = card.SendPhonons([]uint16{index})
	if err != nil {
		t.Error("Unable to send phonons to prove pairing: " + err.Error())
		t.FailNow()
	}
	// test pairing with mismatching certs
}

func TestReceivePhonons(t *testing.T) {
	_, sess, mock := cardPairHappy()
	keyIndex, generatedPubKey, err := mock.CreatePhonon()
	if err != nil {
		t.Error("unable to create mock phonon" + err.Error())
		t.FailNow()

	}
	mock.SetDescriptor(&model.Phonon{
		CurveType: model.Secp256k1,
		Denomination: model.Denomination{
			Base:     1,
			Exponent: 1,
		},
		CurrencyType: 1,
	})
	err = mock.SendPhonons([]uint16{uint16(keyIndex)})
	if err != nil {
		t.Error("Unable to send phonon from mock" + err.Error())
		t.FailNow()

	}
	phononsReceived, err := sess.ListPhonons(0, uint64(0), uint64(0))
	if err != nil {
		t.Error("Unable to list phonons on receiving card: " + err.Error())
		t.FailNow()

	}
	if len(phononsReceived) != 1 {
		t.Error("Did not receive proper number of phonons from listPhonons")
		t.FailNow()

	}

	phononsReceived[0].PubKey, err = sess.GetPhononPubKey(1, model.Secp256k1)
	if err != nil {
		t.Error("Unable to receive public key from received phonon: " + err.Error())
		t.FailNow()

	}
	generatedPubKey, err = model.NewPhononPubKey(generatedPubKey.Bytes(), model.Secp256k1)
	if !phononsReceived[0].PubKey.Equal(generatedPubKey) {
		t.Error("pubkey received on card from phonon generated on mock doesn't match")
		t.FailNow()

	}
	privKey, err := sess.DestroyPhonon(uint16(1))
	if err != nil {
		t.Error("Unable to destroy phonon: " + err.Error())
		t.FailNow()

	}

	destroyedPubKey, err := model.NewPhononPubKey(ethcrypto.FromECDSAPub(&privKey.PublicKey), model.Secp256k1)
	if err != nil {
		t.Error("unable to generate phononpubkey from private key")
		t.FailNow()
	}
	if !phononsReceived[0].PubKey.Equal(destroyedPubKey) {
		t.Error("destroyed phonon private key does not match public key")
		t.FailNow()
	}

	// test receive phonon with unknown curveType
	keyIndex, generatedPubKey, err = mock.CreatePhonon()
	if err != nil {
		t.Error("Unable to generate phonon on mock: " + err.Error())
		t.FailNow()

	}
	mock.SetDescriptor(&model.Phonon{
		CurveType: model.CurveType(68),
		Denomination: model.Denomination{
			Base:     1,
			Exponent: 1,
		},
		CurrencyType: 1,
	})
	err = mock.SendPhonons([]uint16{uint16(keyIndex)})
	if err != nil {
		t.Error("Unable to send phonon from mock" + err.Error())
		t.FailNow()

	}
	phononsReceived, err = sess.ListPhonons(0, uint64(0), uint64(0))
	if err != nil {
		t.Error("Unable to list phonons on receiving card: " + err.Error())
		t.FailNow()

	}
	if len(phononsReceived) != 1 {
		t.Error("Did not receive proper number of phonons from listPhonons")
		t.FailNow()

	}

	phononsReceived[0].PubKey, err = sess.GetPhononPubKey(1, model.Secp256k1)
	if err != nil {
		t.Error("Unable to receive public key from received phonon: " + err.Error())
		t.FailNow()

	}
	// this doesn't make a whole lot of sense to test, but verifies arbitrary data can be retrieved
	privKey, err = sess.DestroyPhonon(uint16(1))
	if err != nil {
		t.Error("Unable to destroy phonon: " + err.Error())
		t.FailNow()

	}
	destroyedPubKey, err = model.NewPhononPubKey(ethcrypto.FromECDSAPub(&privKey.PublicKey), model.Secp256k1)
	if err != nil {
		t.Error("Unable to generate phononpubkey from private key")
		t.FailNow()
	}
	if !destroyedPubKey.Equal(generatedPubKey) {
		t.Error("Destroyed phonon private key does not match public key")
		t.FailNow()

	}
	// test receive phonon with max values on denomination
	keyIndex, generatedPubKey, err = mock.CreatePhonon()
	if err != nil {
		t.Error("unable to create mock phonon" + err.Error())
		t.FailNow()

	}

	mock.SetDescriptor(&model.Phonon{
		CurveType: model.Secp256k1,
		Denomination: model.Denomination{
			Base:     255,
			Exponent: 255,
		},
		CurrencyType: 1,
	})
	err = mock.SendPhonons([]uint16{uint16(keyIndex)})
	if err != nil {
		t.Error("Unable to send phonon from mock" + err.Error())
		t.FailNow()

	}
	phononsReceived, err = sess.ListPhonons(0, uint64(0), uint64(0))
	if err != nil {
		t.Error("Unable to list phonons on receiving card: " + err.Error())
		t.FailNow()

	}
	if len(phononsReceived) != 1 {
		t.Error("Did not receive proper number of phonons from listPhonons")
		t.FailNow()

	}

	phononsReceived[0].PubKey, err = sess.GetPhononPubKey(1, model.Secp256k1)
	if err != nil {
		t.Error("Unable to receive public key from received phonon: " + err.Error())
		t.FailNow()

	}
	if !phononsReceived[0].PubKey.Equal(generatedPubKey) {
		t.Error("pubkey received on card from phonon generated on mock doesn't match")
		t.FailNow()

	}
	privKey, err = sess.DestroyPhonon(uint16(1))
	if err != nil {
		t.Error("Unable to destroy phonon: " + err.Error())
		t.FailNow()

	}
	destroyedPubKey, err = model.NewPhononPubKey(ethcrypto.FromECDSAPub(&privKey.PublicKey), model.Secp256k1)
	if err != nil {
		t.Error("Unable to generate phononpubkey from private key")
		t.FailNow()
	}
	if !phononsReceived[0].PubKey.Equal(destroyedPubKey) {
		t.Error("Destroyed phonon private key does not match public key")
		t.FailNow()

	}

	// test receive phonon with max currency type
	keyIndex, generatedPubKey, err = mock.CreatePhonon()
	if err != nil {
		t.Error("unable to create mock phonon" + err.Error())
		t.FailNow()

	}
	mock.SetDescriptor(&model.Phonon{
		CurveType: model.Secp256k1,
		Denomination: model.Denomination{
			Base:     255,
			Exponent: 255,
		},
		CurrencyType: model.CurrencyType(65535),
	})
	err = mock.SendPhonons([]uint16{uint16(keyIndex)})
	if err != nil {
		t.Error("Unable to send phonon from mock" + err.Error())
		t.FailNow()

	}
	phononsReceived, err = sess.ListPhonons(0, uint64(0), uint64(0))
	if err != nil {
		t.Error("Unable to list phonons on receiving card: " + err.Error())
		t.FailNow()

	}
	if len(phononsReceived) != 1 {
		t.Error("Did not receive proper number of phonons from listPhonons")
		t.FailNow()

	}

	phononsReceived[0].PubKey, err = sess.GetPhononPubKey(1, model.Secp256k1)
	if err != nil {
		t.Error("Unable to receive public key from received phonon: " + err.Error())
		t.FailNow()

	}
	phononsReceived[0].PubKey, err = sess.GetPhononPubKey(1, model.Secp256k1)
	if err != nil {
		t.Error("Unable to receive public key from received phonon: " + err.Error())
		t.FailNow()

	}
	if !phononsReceived[0].PubKey.Equal(generatedPubKey) {
		t.Error("pubkey received on card from phonon generated on mock doesn't match")
		t.FailNow()

	}
	privKey, err = sess.DestroyPhonon(uint16(1))
	if err != nil {
		t.Error("Unable to destroy phonon: " + err.Error())
		t.FailNow()

	}
	destroyedPubKey, err = model.NewPhononPubKey(ethcrypto.FromECDSAPub(&privKey.PublicKey), model.Secp256k1)
	if err != nil {
		t.Error("Unable to generate phononpubkey from private key")
		t.FailNow()
	}
	if !phononsReceived[0].PubKey.Equal(destroyedPubKey) {
		t.Error("Destroyed phonon private key does not match public key")
		t.FailNow()

	}

	//test multiple receive
	keyIndex, generatedPubKey, err = mock.CreatePhonon()
	if err != nil {
		t.Error("unable to create mock phonon" + err.Error())
		t.FailNow()

	}
	mock.SetDescriptor(&model.Phonon{
		CurveType: model.Secp256k1,
		Denomination: model.Denomination{
			Base:     1,
			Exponent: 1,
		},
		CurrencyType: 1,
	})
	keyIndex2, generatedPubKey, err := mock.CreatePhonon()
	if err != nil {
		t.Error("unable to create mock phonon" + err.Error())
		t.FailNow()

	}
	mock.SetDescriptor(&model.Phonon{
		CurveType: model.Secp256k1,
		Denomination: model.Denomination{
			Base:     1,
			Exponent: 1,
		},
		CurrencyType: 1,
	})
	err = mock.SendPhonons([]uint16{keyIndex, keyIndex2})
	if err != nil {
		t.Error("Unable to receive multiple phonons: " + err.Error())
		t.FailNow()
	}
}

func TestFriendlyName(t *testing.T) {
	cs := unlockHappy()
	err := cs.SetFriendlyName("abc")
	if err != nil {
		t.Error("Unable to set friendly name: " + err.Error())
		t.FailNow()

	}
	name, err := cs.GetFriendlyName()
	if err != nil {
		t.Error("Unable to get friendly name: " + err.Error())
		t.FailNow()

	}
	if name != "abc" {
		t.Error("friendly name isn't what was sent: " + err.Error())
		t.FailNow()

	}
	//invalid length name > max 32 bytes and < APDU max 256
	err = cs.SetFriendlyName(string(util.RandomKey(150)))
	if err == nil {
		t.Error("Set Friendly Name didn't fail on name too long")
		t.FailNow()

	}
	if name != "abc" {
		t.Error("friendly name isn't what was sent: " + err.Error())
		t.FailNow()

	}

	// emoji
	err = cs.SetFriendlyName("abcdefg")
	if err != nil {
		t.Error("Unable to set friendly name: " + err.Error())
		t.FailNow()

	}
	name, err = cs.GetFriendlyName()
	if err != nil {
		t.Error("Unable to get friendly name: " + err.Error())
		t.FailNow()

	}
	if name != "abcdefg" {
		t.Error("friendly name isn't what was sent: should have been 😀, and was " + name)
		t.FailNow()

	}

}

func TestSendPhonons(t *testing.T) {
	cs, cardSess, mock := cardPairHappy()
	index, pubKey, err := cs.CreatePhonon(model.Secp256k1)
	if err != nil {
		t.Error("Unable to create phonon: " + err.Error())
		t.FailNow()

	}
	testPhonon := &model.Phonon{
		KeyIndex: index,
		Denomination: model.Denomination{
			Base:     1,
			Exponent: 1,
		},
		CurrencyType: 1,
	}
	err = cardSess.SetDescriptor(testPhonon)
	err = cardSess.SendPhonons([]uint16{index})
	if err != nil {
		t.Error("Unable to send phonon: " + err.Error())
		t.FailNow()

	}
	mockReceivedPhonons, err := mock.ListPhonons(0, 0, 0)
	if err != nil {
		t.Error("Error received on listing phonons from mock card: " + err.Error())
		t.FailNow()

	}
	if mockReceivedPhonons[0].Denomination.Base != 1 || mockReceivedPhonons[0].Denomination.Exponent != 1 || mockReceivedPhonons[0].CurrencyType != model.Bitcoin {
		t.Error(fmt.Sprintf("phonon received on mock\n %+v\nwas not the same as phonon sent from real card\n %+v\n", mockReceivedPhonons[0], testPhonon))
		t.FailNow()

	}
	mockKey, err := mock.GetPhononPubKey(uint16(0), model.Secp256k1)
	if err != nil {
		t.Error("Error received from getPhononPubKey on mock after sendPhonon: " + err.Error())
		t.FailNow()

	}
	if !mockKey.Equal(pubKey) {
		t.Error("Key receved from sendPhonons not equal to key found on create")
		t.FailNow()

	}
	privKey, err := mock.DestroyPhonon(uint16(0))
	if err != nil {
		t.Error("Unable to retrieve private key from mock after sendPhonnons")
		t.FailNow()

	}
	destroyedPubKey, err := model.NewPhononPubKey(ethcrypto.FromECDSAPub(&privKey.PublicKey), model.Secp256k1)
	if err != nil {
		t.Error("Unable to generate phononpubkey from private key")
		t.FailNow()
	}
	if !mockKey.Equal(destroyedPubKey) {
		t.Error("Private key retrieved from sent phonon not equal to public key generated")
		t.FailNow()

	}
	// test extended tlv
}

func TestStorageBoundaries(t *testing.T) {
	cs := createPhononHappy(maxPhononStorageAmount)
	_, _, err := cs.CreatePhonon(model.Secp256k1)
	if err == nil {
		t.Error("create phonon with full phonon table should have failed, but didn't")
		t.FailNow()
	}
	term := orchestrator.NewPhononTerminal()

	cardSession, err := orchestrator.NewSession(cs)
	if err != nil {
		t.Error("Unable to create card session from command set: " + err.Error())
		t.FailNow()
	}
	term.AddSession(cardSession)
	mockID, err := term.GenerateMock()
	if err != nil {
		t.Error("unable to generate mock: " + err.Error())
		t.FailNow()
	}
	cardSession.VerifyPIN("111111")
	mockSess := term.SessionFromID(mockID)
	mockSess.VerifyPIN("111111")
	mockIndex, _, err := mockSess.CreatePhonon()
	if err != nil {
		t.Error("Unable to create phonon on mock: " + err.Error())
		t.FailNow()
	}
	err = mockSess.ConnectToLocalProvider()
	if err != nil {
		t.Error("unable to connect mock session to local provider: " + err.Error())
		t.FailNow()
	}
	err = cardSession.ConnectToLocalProvider()
	if err != nil {
		t.Error("Unable to connect card session to local provider: " + err.Error())
		t.FailNow()
	}
	err = cardSession.ConnectToCounterparty(mockID)
	if err != nil {
		t.Error("unable to connect to mock counterparty: " + err.Error())
		t.FailNow()
	}
	err = mockSess.SendPhonons([]uint16{mockIndex})
	//need to do the rest of this with a mock cs to generate the packet, and then attempt to receive it on the cs.
}

func TestMinePhonon(t *testing.T) {
	cs, cardSess, mock := cardPairHappy()
	err := errors.New("native phonon mine attempt failed")
	var index uint16
	for err != nil && err.Error() == "native phonon mine attempt failed" {
		index, _, err = cs.MineNativePhonon(uint8(1))
	}
	if err != nil {
		t.Error("Unable to mine native phonon: " + err.Error())
		t.FailNow()
	}
	err = cardSess.ConnectToLocalProvider()
	if err != nil {
		t.Error("Unable to connect card to local remote provider: " + err.Error())
		t.FailNow()
	}
	mock.VerifyPIN("111111")
	err = mock.ConnectToLocalProvider()
	if err != nil {
		t.Error("unable to connect mock to local remote provider: " + err.Error())
		t.FailNow()
	}
	err = cardSess.ConnectToCounterparty(mock.GetName())
	if err != nil {
		t.Error("unable to pair with mock session: " + err.Error())
		t.FailNow()
	}
	err = cardSess.SendPhonons([]uint16{index})
	if err != nil {
		t.Error("unable to send native phonon to mock receiver: " + err.Error())
		t.FailNow()
	}
}
