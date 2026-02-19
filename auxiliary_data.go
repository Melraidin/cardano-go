package cardano

import (
	"reflect"

	"github.com/melraidin/cardano-go/internal/cbor"
)

// Metadata represents the transaction metadata.
type Metadata map[uint]interface{}

// AuxiliaryData is the auxiliary data in the transaction.
type AuxiliaryData struct {
	Metadata      Metadata    `cbor:"0,keyasint,omitempty"`
	NativeScripts interface{} `cbor:"1,keyasint,omitempty"`
	PlutusScripts interface{} `cbor:"2,keyasint,omitempty"`
}

// MarshalCBOR implements cbor.Marshaler
func (d *AuxiliaryData) MarshalCBOR() ([]byte, error) {
	type auxiliaryData AuxiliaryData

	// Register tag 259 for maps
	tags, err := d.tagSet(auxiliaryData{})
	if err != nil {
		return nil, err
	}

	em, err := cbor.CanonicalEncOptions().EncModeWithTags(tags)
	if err != nil {
		return nil, err
	}

	return em.Marshal(auxiliaryData(*d))
}

// UnmarshalCBOR implements cbor.Unmarshaler
func (d *AuxiliaryData) UnmarshalCBOR(data []byte) error {
	type auxiliaryData AuxiliaryData

	// Alonzo+ auxiliary data is CBOR tag 259. Legacy metadata is an untagged map.
	// Support both forms to decode externally generated transactions.
	if hasCBORTag(stripSelfDescribedCBORTag(data)) {
		tags, err := d.tagSet(auxiliaryData{})
		if err != nil {
			return err
		}

		dm, err := cbor.DecOptions{
			MapKeyByteString: cbor.MapKeyByteStringWrap,
		}.DecModeWithSharedTags(tags)
		if err != nil {
			return err
		}

		var dd auxiliaryData
		if err := dm.Unmarshal(data, &dd); err != nil {
			return err
		}

		*d = AuxiliaryData(dd)
		return nil
	}

	dm, err := cbor.DecOptions{
		MapKeyByteString: cbor.MapKeyByteStringWrap,
	}.DecMode()
	if err != nil {
		return err
	}

	var md Metadata
	if err := dm.Unmarshal(data, &md); err != nil {
		return err
	}

	d.Metadata = md
	d.NativeScripts = nil
	d.PlutusScripts = nil
	return nil
}

func (d *AuxiliaryData) tagSet(contentType interface{}) (cbor.TagSet, error) {
	tags := cbor.NewTagSet()
	err := tags.Add(
		cbor.TagOptions{EncTag: cbor.EncTagRequired, DecTag: cbor.DecTagRequired},
		reflect.TypeOf(contentType),
		259)
	if err != nil {
		return nil, err
	}

	return tags, nil
}

func stripSelfDescribedCBORTag(data []byte) []byte {
	for len(data) >= 3 && data[0] == 0xd9 && data[1] == 0xd9 && data[2] == 0xf7 {
		data = data[3:]
	}
	return data
}

func hasCBORTag(data []byte) bool {
	return len(data) > 0 && (data[0]&0xe0) == 0xc0
}
