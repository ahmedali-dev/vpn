package main

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"unicode/utf8"
)

const compactSharePrefix = "TN2."
const protectedSharePrefix = "TN2P."

// This order is part of format version 2. Append new options; never reorder.
var compactShareFlags = []string{
	"-mode", "-H", "-P", "-u", "-p", "-S", "-socks-port", "-pac-port", "-max-conns", "-tls-version",
	"-ssh-host-key", "-ssh-cert-sha256", "-proxy", "-payload-stage", "-v2ray-link", "-v2ray-sni", "-v2ray-cert-sha256",
	"-v2ray-protocol", "-v2ray-uuid", "-v2ray-addr", "-v2ray-port", "-v2ray-network", "-v2ray-security", "-v2ray-path",
	"-v2ray-host", "-v2ray-service", "-tun", "-auto-route", "-ssh-trust-on-first-use",
}

func writeShareBytes(out *bytes.Buffer, value []byte) {
	var length [binary.MaxVarintLen64]byte
	count := binary.PutUvarint(length[:], uint64(len(value)))
	out.Write(length[:count])
	out.Write(value)
}
func readShareBytes(in *bytes.Reader, limit int) ([]byte, error) {
	length, err := binary.ReadUvarint(in)
	if err != nil || length > uint64(limit) || length > uint64(in.Len()) {
		return nil, fmt.Errorf("invalid compact field length")
	}
	value := make([]byte, int(length))
	_, err = io.ReadFull(in, value)
	return value, err
}

// Binary option IDs avoid repeated flag names. VMess's nested base64 is decoded
// before compression and restored byte-for-byte on import, including its alphabet.
func packProfileShare(p sharedProfile) ([]byte, error) {
	var out bytes.Buffer
	mode := byte(0)
	if p.Mode == "xray" {
		mode = 1
	} else if p.Mode == "v2ray" {
		mode = 2
	}
	out.WriteByte(mode)
	writeShareBytes(&out, []byte(p.Name))
	for i := 0; i < len(p.Args); i++ {
		flag := p.Args[i]
		index := -1
		for j, name := range compactShareFlags {
			if flag == name {
				index = j
				break
			}
		}
		if index < 0 {
			return nil, fmt.Errorf("unsupported compact option")
		}
		out.WriteByte(byte(index))
		if flag == "-tun" || flag == "-auto-route" || flag == "-ssh-trust-on-first-use" {
			continue
		}
		i++
		value := []byte(p.Args[i])
		kind := byte(0)
		if flag == "-v2ray-link" && bytes.HasPrefix(value, []byte("vmess://")) {
			encoded := strings.TrimPrefix(string(value), "vmess://")
			for j, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
				decoded, err := encoding.DecodeString(encoded)
				if err == nil && encoding.EncodeToString(decoded) == encoded {
					kind = byte(j + 1)
					value = decoded
					break
				}
			}
		}
		out.WriteByte(kind)
		writeShareBytes(&out, value)
	}
	if out.Len() > maxSharePayload {
		return nil, fmt.Errorf("profile is too large to share")
	}
	return out.Bytes(), nil
}
func unpackProfileShare(data []byte) (sharedProfile, error) {
	in := bytes.NewReader(data)
	mode, err := in.ReadByte()
	if err != nil || mode > 2 {
		return sharedProfile{}, fmt.Errorf("invalid compact profile mode")
	}
	name, err := readShareBytes(in, 100)
	if err != nil {
		return sharedProfile{}, err
	}
	p := sharedProfile{Name: string(name), Mode: []string{"ssh", "xray", "v2ray"}[mode]}
	for in.Len() > 0 {
		index, err := in.ReadByte()
		if err != nil || int(index) >= len(compactShareFlags) {
			return p, fmt.Errorf("invalid compact profile option")
		}
		flag := compactShareFlags[index]
		p.Args = append(p.Args, flag)
		if len(p.Args) > 128 {
			return p, fmt.Errorf("too many profile arguments")
		}
		if flag == "-tun" || flag == "-auto-route" || flag == "-ssh-trust-on-first-use" {
			continue
		}
		kind, err := in.ReadByte()
		if err != nil {
			return p, fmt.Errorf("missing compact option value")
		}
		value, err := readShareBytes(in, 8192)
		if err != nil {
			return p, err
		}
		if kind > 0 {
			if flag != "-v2ray-link" || kind > 4 {
				return p, fmt.Errorf("invalid compact value type")
			}
			encoding := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}[kind-1]
			value = []byte("vmess://" + encoding.EncodeToString(value))
		}
		if !utf8.Valid(value) {
			return p, fmt.Errorf("invalid compact text")
		}
		p.Args = append(p.Args, string(value))
	}
	return validateSharedProfile(p)
}
func compressShare(data []byte) ([]byte, error) {
	var out bytes.Buffer
	writer, _ := flate.NewWriter(&out, flate.BestCompression)
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if out.Len()+1 < len(data)+1 {
		return append([]byte{1}, out.Bytes()...), nil
	}
	return append([]byte{0}, data...), nil
}
func inflateShare(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("invalid compact profile")
	}
	if data[0] == 0 {
		if len(data)-1 > maxSharePayload {
			return nil, fmt.Errorf("profile is too large")
		}
		return data[1:], nil
	}
	if data[0] != 1 {
		return nil, fmt.Errorf("unsupported profile compression")
	}
	reader := flate.NewReader(bytes.NewReader(data[1:]))
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, maxSharePayload+1))
	if err != nil || len(raw) > maxSharePayload {
		return nil, fmt.Errorf("invalid or oversized compact profile")
	}
	return raw, nil
}

func encodeProfileShare(p savedProfile, password string) (string, error) {
	portable, err := portableProfile(p)
	if err != nil {
		return "", err
	}
	packed, err := packProfileShare(portable)
	if err != nil {
		return "", err
	}
	compressed, err := compressShare(packed)
	if err != nil {
		return "", err
	}
	prefix := compactSharePrefix
	var envelope []byte
	if password == "" {
		envelope = make([]byte, 4, len(compressed)+4)
		binary.BigEndian.PutUint32(envelope, crc32.ChecksumIEEE(compressed))
		envelope = append(envelope, compressed...)
	} else {
		prefix = protectedSharePrefix
		salt := make([]byte, 16)
		if _, err = rand.Read(salt); err != nil {
			return "", err
		}
		aead, err := shareCipher(password, salt)
		if err != nil {
			return "", err
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err = rand.Read(nonce); err != nil {
			return "", err
		}
		envelope = append(salt, nonce...)
		envelope = aead.Seal(envelope, nonce, compressed, []byte(prefix))
	}
	code := prefix + base64.RawURLEncoding.EncodeToString(envelope)
	if len(code) > maxShareCode {
		return "", fmt.Errorf("profile is too large to share")
	}
	return code, nil
}
func decodeProfileShare(code, password string) (savedProfile, error) {
	code = strings.TrimSpace(code)
	if strings.HasPrefix(code, sharePrefix) {
		return decodeLegacyProfileShare(code, password)
	}
	if len(code) > maxShareCode {
		return savedProfile{}, fmt.Errorf("profile is too large")
	}
	prefix := compactSharePrefix
	protected := strings.HasPrefix(code, protectedSharePrefix)
	if protected {
		prefix = protectedSharePrefix
	} else if !strings.HasPrefix(code, compactSharePrefix) {
		return savedProfile{}, fmt.Errorf("invalid or unsupported TunnelNest share code")
	}
	envelope, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, prefix))
	if err != nil {
		return savedProfile{}, fmt.Errorf("invalid share code")
	}
	var compressed []byte
	if protected {
		if len(envelope) < 44 {
			return savedProfile{}, fmt.Errorf("invalid protected share code")
		}
		aead, err := shareCipher(password, envelope[:16])
		if err != nil {
			return savedProfile{}, err
		}
		compressed, err = aead.Open(nil, envelope[16:28], envelope[28:], []byte(prefix))
		if err != nil {
			return savedProfile{}, fmt.Errorf("incorrect password or damaged share code")
		}
	} else {
		if len(envelope) < 6 || crc32.ChecksumIEEE(envelope[4:]) != binary.BigEndian.Uint32(envelope[:4]) {
			return savedProfile{}, fmt.Errorf("damaged share code")
		}
		compressed = envelope[4:]
	}
	packed, err := inflateShare(compressed)
	if err != nil {
		return savedProfile{}, err
	}
	profile, err := unpackProfileShare(packed)
	if err != nil {
		return savedProfile{}, err
	}
	return savedProfile{Name: profile.Name, Mode: profile.Mode, Args: profile.Args}, nil
}
