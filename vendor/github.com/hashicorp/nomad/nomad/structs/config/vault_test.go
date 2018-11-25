package config

import (
	"reflect"
	"testing"
)

func TestVaultConfig_Merge(t *testing.T) {
	trueValue, falseValue := true, false
	c1 := &VaultConfig{
		Enabled:              &falseValue,
		Token:                "1",
		Role:                 "1",
		AllowUnauthenticated: &trueValue,
		TaskTokenTTL:         "1",
		Addr:                 "1",
		TLSCaFile:            "1",
		TLSCaPath:            "1",
		TLSCertFile:          "1",
		TLSKeyFile:           "1",
		TLSSkipVerify:        &trueValue,
		TLSServerName:        "1",
	}

	c2 := &VaultConfig{
		Enabled:              &trueValue,
		Token:                "2",
		Role:                 "2",
		AllowUnauthenticated: &falseValue,
		TaskTokenTTL:         "2",
		Addr:                 "2",
		TLSCaFile:            "2",
		TLSCaPath:            "2",
		TLSCertFile:          "2",
		TLSKeyFile:           "2",
		TLSSkipVerify:        nil,
		TLSServerName:        "2",
	}

	e := &VaultConfig{
		Enabled:              &trueValue,
		Token:                "2",
		Role:                 "2",
		AllowUnauthenticated: &falseValue,
		TaskTokenTTL:         "2",
		Addr:                 "2",
		TLSCaFile:            "2",
		TLSCaPath:            "2",
		TLSCertFile:          "2",
		TLSKeyFile:           "2",
		TLSSkipVerify:        &trueValue,
		TLSServerName:        "2",
	}

	result := c1.Merge(c2)
	if !reflect.DeepEqual(result, e) {
		t.Fatalf("bad:\n%#v\n%#v", result, e)
	}
}
