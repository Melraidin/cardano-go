package cardano

import (
	"encoding/hex"
	"testing"
)

func TestAuxiliaryDataUnmarshalCBORLegacyMetadata(t *testing.T) {
	// {674: {"msg": ["midnight-reserve:stage-upgrade"]}}
	data, err := hex.DecodeString("a11902a2a1636d736781781e6d69646e696768742d726573657276653a73746167652d75706772616465")
	if err != nil {
		t.Fatal(err)
	}

	var aux AuxiliaryData
	if err := aux.UnmarshalCBOR(data); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	assertAuxiliaryMetadataMessage(t, aux.Metadata, "midnight-reserve:stage-upgrade")
}

func TestAuxiliaryDataUnmarshalCBORTaggedMetadata(t *testing.T) {
	// 259({0: {674: {"msg": ["midnight-reserve:stage-upgrade"]}}})
	data, err := hex.DecodeString("d90103a100a11902a2a1636d736781781e6d69646e696768742d726573657276653a73746167652d75706772616465")
	if err != nil {
		t.Fatal(err)
	}

	var aux AuxiliaryData
	if err := aux.UnmarshalCBOR(data); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	assertAuxiliaryMetadataMessage(t, aux.Metadata, "midnight-reserve:stage-upgrade")
}

func assertAuxiliaryMetadataMessage(t *testing.T, md Metadata, expected string) {
	t.Helper()

	if md == nil {
		t.Fatal("metadata is nil")
	}

	entry, ok := md[674]
	if !ok {
		t.Fatalf("metadata label 674 missing: %#v", md)
	}

	var rawMsgs interface{}
	switch m := entry.(type) {
	case map[interface{}]interface{}:
		rawMsgs = m["msg"]
	case map[string]interface{}:
		rawMsgs = m["msg"]
	default:
		t.Fatalf("unexpected metadata entry type %T", entry)
	}

	switch msgs := rawMsgs.(type) {
	case []interface{}:
		if len(msgs) != 1 {
			t.Fatalf("unexpected message list length: %d", len(msgs))
		}
		if s, ok := msgs[0].(string); !ok || s != expected {
			t.Fatalf("unexpected message value: %#v", msgs[0])
		}
	case []string:
		if len(msgs) != 1 {
			t.Fatalf("unexpected message list length: %d", len(msgs))
		}
		if msgs[0] != expected {
			t.Fatalf("unexpected message value: %q", msgs[0])
		}
	default:
		t.Fatalf("unexpected msg type %T", rawMsgs)
	}
}
